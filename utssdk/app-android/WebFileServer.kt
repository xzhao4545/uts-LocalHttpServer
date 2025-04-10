package com.xzhao.localhttpserver

import android.content.Context
import android.content.res.AssetManager
import fi.iki.elonen.NanoHTTPD
import io.dcloud.uts.console
import java.io.*
import java.net.HttpURLConnection
import java.net.URISyntaxException
import java.net.URL
import java.util.Locale
import java.util.TreeMap
import java.util.logging.Level
import java.util.regex.Pattern


class WebFileServer(context: Context?,staticPath:String, hostname: String?, port: Int) :
    NanoHTTPD(context,staticPath, hostname, port) {
    var cors = false
    override fun serve(session: IHTTPSession): Response {
        LOG.log(Level.ALL,"${session.headers["host"]?:session.remoteHostName} [${session.method?.name}] ${session.uri}")
        //判断是否是跨域请求
        if (isPreflightRequest(session)) {
            return if (this.cors) // 如果是则发送CORS响应告诉浏览HTTP服务支持的METHOD及HEADERS和请求源
                responseCORS(session)
            else newFixedLengthResponse("refuse")
        }
        val uriNodeRes=uriRoot.match(session.uri)
        if(uriNodeRes!=null) {
            val node =uriNodeRes.node
            if(node.proxyPath!=null){
                session.proxy=true
                return proxyRequest(node.proxyPath!!,uriNodeRes.pathVariable["proxyPath"]!!,session)
            }
            if (node.method != null && (node.methodType == Method.REQUEST || node.methodType == session.method)) {
                return node.method!!(session,uriNodeRes.pathVariable)
            }
        }
        if (session.method == Method.GET) {
            if (REQUEST_ROOT == session.uri || session.uri.isEmpty()||session.uri.matches("/[^#?]+\\.\\w+$".toRegex())) {
                return responseFile(session)
            }
        }
        return responseNotFound()
    }
    @Throws(IOException::class,FileNotFoundException::class)
    fun newFixedLengthResponse(
        status: Response.IStatus,
        mimeType: String?,
        file:String
    ): Response {
        val type = file.substring(file.lastIndexOf(".") + 1)
        val mime:String=mimeType ?: getType(type)
        val f=File(file)
        val fis=FileInputStream(f)
        return if(f.length()< RESPONSE_FILE_SIZE_CHUNKED) {
            newFixedLengthResponse(status, mime, fis, fis.available().toLong())
        }else{
            newChunkedResponse(status,mime,fis)
        }
    }
    //向响应包中添加CORS包头
    private fun responseCORS(session: IHTTPSession): Response {
        val resp = wrapResponse(session, newFixedLengthResponse(""))
        val headers = session.headers
        resp.addHeader("Access-Control-Allow-Methods", "POST,GET,OPTIONS")

        val requestHeaders = headers["access-control-request-headers"]
        val allowHeaders = requestHeaders ?: "Content-Type"
        resp.addHeader("Access-Control-Allow-Headers", allowHeaders)
        //resp.addHeader("Access-Control-Max-Age", "86400");
        resp.addHeader("Access-Control-Max-Age", "86400")
        return resp
    }

    //封装响应包
    private fun wrapResponse(session: IHTTPSession, resp: Response): Response {
        val headers = session.headers
        resp.addHeader("Access-Control-Allow-Credentials", "true")
        // 如果请求头中包含'Origin',则响应头中'Access-Control-Allow-Origin'使用此值否则为'*'
        // nanohttd将所有请求头的名称强制转为了小写
        val ori = headers["origin"]
        val origin = ori ?: "*"
        resp.addHeader("Access-Control-Allow-Origin", origin)

        val requestHeaders = headers["access-control-request-headers"]
        if (requestHeaders != null) {
            resp.addHeader("Access-Control-Allow-Headers", requestHeaders)
        }
        return resp
    }

    private fun responseNotFound(): Response {
        return newFixedLengthResponse(Response.Status.NOT_FOUND, "text/plain", "404\nNOT FOUND")
    }
    enum class StaticPath(val typeValue:Int){
        Assets(0),
        Static(1),
        Public(2);

        companion object {
            fun fromTypeValue(typeValue: Int): StaticPath? {
                return entries.find { it.typeValue == typeValue }
            }
        }
    }
    private val staticPaths:MutableMap<StaticPath,String> = hashMapOf(
        StaticPath.Static to "$staticPath/static",
        StaticPath.Assets to "static/public",
        StaticPath.Public to "/storage/emulated/0/Documents/static"
    )
    //该方法需在服务器开启前调用
    fun updateStaticMimeFilePath(path:String){
        this.staticMimeFilePath=path
    }
    var staticPathType:StaticPath=StaticPath.Assets
        private set
    /**
     * 更新静态资源文件路径，其中path可省略，将使用默认路径
     * @param staticFilePathType 要更改的静态资源文件路径类型
     * @param path 要更改的静态资源文件路径
     */
    fun updateStaticFilePathType(staticFilePathType: Int,path:String?=null):Boolean{
        staticPathType=StaticPath.fromTypeValue(staticFilePathType)?:return false
        if(path!=null){
            staticPaths[staticPathType]=path
        }
        return true
    }
    fun updateStaticFilePath(path:String){
        staticPaths[staticPathType]=path
    }
    fun getStaticFilePath():String{
        return staticPaths[staticPathType]!!
    }
    private val assets:AssetManager=this.context!!.assets
    @Throws(IOException::class,FileNotFoundException::class)
    private fun getStaticFileInputStream(filePath:String):InputStream{
        val path=concatPath(staticPaths[staticPathType]!!,filePath)
        return when(staticPathType){
            StaticPath.Assets -> assets.open(path)
            StaticPath.Static -> FileInputStream(File(path))
            StaticPath.Public -> FileInputStream(File(path))
        }
    }
    private fun responseFile(session: IHTTPSession): Response {
        try {
            val filePath =if(REQUEST_ROOT == session.uri || session.uri.isEmpty())
                "index.html"
            else
                session.uri
            val type = filePath.substring(filePath.lastIndexOf(".") + 1)
            //文件输入流
            val fis = getStaticFileInputStream(filePath)
            return newFixedLengthResponse(Response.Status.OK, getType(type), fis, fis.available().toLong())
        } catch (e: FileNotFoundException) {
            LOG.severe(e.message,e.stackTraceToString())
            LOG.log(Level.WARNING,"file not found: ${e.message}")
        } catch (e: IOException) {
            LOG.severe(e.message,e.stackTraceToString())
            LOG.log(Level.WARNING,"throw IOException when open file ${e.message}")
        }
        return newFixedLengthResponse(Response.Status.NOT_FOUND, "text/plain", "404\nNOT FOUND")
    }

    private fun getType(fileType: String): String {
        val type=this.getMimeTypeForFile(fileType)
        if(type!=null)
            return type
        when (fileType.lowercase(Locale.getDefault())) {
            "js" -> return "text/javascript"
            "css" -> return "text/css"
            "html" -> return "text/html"
            "text" -> return "text/plain"
            "xml" -> return "text/xml"
            "gif" -> return "image/gif"
            "jpg" -> return "image/jpeg"
            "png" -> return "image/png"
            "ico" -> return "image/x-icon"
        }
        return "application/octet-stream"
    }
    private val uriRoot:UriNode<(IHTTPSession,MutableMap<String,String>)->Response> =UriNode(null)
    fun addUriMethod(methodType:String,uri:String,method: (IHTTPSession,MutableMap<String,String>)->Response){
        val mt=Method.lookup(methodType)
        if(mt==null){
            LOG.severe("unknown method type:$methodType")
        }
        uriRoot.construct(mt!!,uri,method)
    }
    fun addProxyPath(uri:String,targetHost:String){
        uriRoot.constructProxy(uri,targetHost)
    }
    companion object {
        //根目录
        private const val REQUEST_ROOT = "/"
        const val RESPONSE_FILE_SIZE_CHUNKED=20*1024*1024
        //判断是否为跨域请求
        private fun isPreflightRequest(session: IHTTPSession): Boolean {
            val headers = session.headers
            return (Method.OPTIONS == session.method && headers.containsKey("origin")
                    && headers.containsKey("access-control-request-method")
                    && headers.containsKey("access-control-request-headers"))
        }
        private val pathPattern:Pattern=Pattern.compile("/{2,}")
        fun concatPath(vararg paths:String):String{
            val sb:StringBuilder=java.lang.StringBuilder()
            for (p in paths){
                if(sb.isNotEmpty()&&p[0]!='/'&&p[0]!='\\')
                    sb.append('/')
                sb.append(p)
            }
            val m=pathPattern.matcher(sb)
            return m.replaceAll("/")
        }
        fun simplifyPath(path:String):String{
            val m=pathPattern.matcher(path)
            val s=m.replaceAll("/")
            val l=if(s.last()=='/') s.length-1 else s.length
            val f=if(s.first()=='/') 1 else 0
            return s.substring(f,l)
        }
        fun splitUri(uri:String):List<String>{
            return uri.split('/').filter { it.isNotEmpty() }
        }
    }
    inner class UriNode<T>(var root:UriNode<T>?){
        private var variableKey:String? =null
        private var variableValue:UriNode<T>?=null
        private val nodeMap:MutableMap<String,UriNode<T>> =HashMap()
        var proxyPath:String?=null
            private set
        var method:T?=null
            private set
        var methodType:Method?=null
            private set
        init{
            if(root==null){
                root=this
            }
        }
        fun construct(methodType: Method,uri:String,method:T){
            val nodes= splitUri(uri)
            try {
                val node = root!!.construct(nodes, 0)
                node.method = method
                node.methodType = methodType
            }catch (e:URISyntaxException){
                val uriE=URISyntaxException(uri,e.reason)
                LOG.log(Level.SEVERE,uriE)
                throw uriE
            }
        }
        fun constructProxy(uri:String,targetHost: String){
            val nodes= splitUri(uri)
            try {
                val node = root!!.construct(nodes, 0)
                node.proxyPath=targetHost
                if(node.variableKey!=null){
                    node.variableKey=null
                    node.variableValue=null
                }
                node.nodeMap.clear()
            }catch (e:URISyntaxException){
                val uriE=URISyntaxException(uri,e.reason)
                LOG.log(Level.SEVERE,uriE)
                throw uriE
            }
        }

        /**
         * 递归调用
         */
        private fun construct(nodes:List<String>,ind:Int):UriNode<T>{
            if(ind==nodes.size){
                return this
            }
            if(proxyPath!=null){
                throw URISyntaxException(null,"There is already a proxy path $proxyPath.")
            }
            val s=nodes[ind]
            if(s.startsWith('{')&&s.endsWith('}')){
                val v=s.substring(1,s.length-1)
                if(variableKey==null){
                    variableKey=v
                    variableValue = UriNode(root)
                }else if(variableKey!=v){
                    throw URISyntaxException(null,"There is already a path parameter {${variableKey}}, and the newly added path parameter name ($s) is different from the existing one.")
                }
                return variableValue!!.construct(nodes,ind+1)
            }
            if(!nodeMap.containsKey(s)){
                nodeMap[s]=UriNode(root)
            }
            return nodeMap[s]!!.construct(nodes,ind+1)
        }
        fun match(uri:String):UriMatchResult<T>?{
            var uriNode=this
            val nodes= splitUri(uri)
            val map:MutableMap<String,String> =TreeMap()
            var node: String
            for(ind in nodes.indices){
                node=nodes[ind]
                if(uriNode.proxyPath!=null){
                    val sb=java.lang.StringBuilder()
                    for(i in ind..<nodes.size){
                        sb.append('/').append(nodes[i])
                    }
                    map["proxyPath"]=sb.toString()
                    return UriMatchResult(uriNode,map)
                }
                if(uriNode.nodeMap.containsKey(node)){
                    uriNode=uriNode.nodeMap[node]!!
                    continue
                }
                if(uriNode.variableKey!=null) {
                    map[uriNode.variableKey!!] = node
                    uriNode=uriNode.variableValue!!
                }
                else{
                    return null
                }
            }
            return if(uriNode.method==null){
                null
            }else{
                UriMatchResult(uriNode,map)
            }
        }
    }
    class UriMatchResult<T>(val node:UriNode<T>,val pathVariable:MutableMap<String,String>)
    private fun proxyRequest(targetUrl: String,apUrl:String, session: IHTTPSession): Response {
        return try {
            session.queryParameterString
            session.getParameters()
            val method=session.method!!.name
            var turl=targetUrl+apUrl
            if(session.queryParameterString!=null){
                turl+="?${session.queryParameterString}"
            }
			LOG.all("proxy: $turl")
            val url = URL(turl)
            val connection = url.openConnection() as HttpURLConnection
            connection.requestMethod = method
            connection.doInput = true
			
            // 复制请求头（避免 Host 头部冲突）
            session.headers.forEach { (key, value) ->
                if (!key.equals("host", ignoreCase = true)) {
                    connection.setRequestProperty(key, value)
                }
            }
            // 读取服务器响应
            val responseCode = connection.responseCode
            val responseStream = if (responseCode < 400) connection.inputStream else connection.errorStream
            val mimeType = connection.contentType ?: "application/octet-stream"

            // 发送回客户端
            val response = newChunkedResponse(Response.Status.lookup(responseCode) ?: Response.Status.OK, mimeType,responseStream)

            // 复制响应头
            connection.headerFields.forEach { (key, values) ->
                if (key != null&&!key.equals("content-type", ignoreCase = true)
                    && !key.equals("Transfer-Encoding", ignoreCase = true)
                    && values.isNotEmpty()) {
                    response.addHeader(key, values.joinToString("; "))
                }
            }

            response
        } catch (e: Exception) {
            LOG.severe(e.message,e.stackTraceToString())
            newFixedLengthResponse(Response.Status.BAD_REQUEST, MIME_PLAINTEXT,"Proxy Request Failed: ${e.message}")
        }
    }
}
class LOG{
    companion object{
        private var levelValue:Int=Level.WARNING.intValue()
        private val levelOff=Level.OFF.intValue()
        fun updateLevel(level: Level){
            levelValue=level.intValue()
        }
        fun log(level:Level,vararg msg:Any?){
            if(!isLoggable(level)){
                return
            }
            console.log("[${level.name}]\t",*msg)
        }
        fun warning(vararg msg:Any?){
            log(Level.WARNING,*msg)
        }
        fun severe(vararg msg:Any?){
            log(Level.SEVERE,*msg)
        }
		fun all(vararg msg:Any?){
		    log(Level.ALL,*msg)
		}
        fun setLevel(level:Int){
            if(level<0){
                levelValue= Int.MAX_VALUE
            }else if(level==0){
                levelValue=Int.MIN_VALUE
            }else {
                levelValue = level
            }
        }
        fun isLoggable(level: Level): Boolean {
            return !(level.intValue() < levelValue || levelValue == levelOff)
        }
    }
}