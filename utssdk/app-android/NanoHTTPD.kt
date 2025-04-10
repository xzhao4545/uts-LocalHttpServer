package fi.iki.elonen /*
 * #%L
 * NanoHttpd-Core
 * %%
 * Copyright (C) 2012 - 2015 nanohttpd
 * %%
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the nanohttpd nor the names of its contributors
 *    may be used to endorse or promote products derived from this software without
 *    specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * #L%
 */

import android.content.Context
import fi.iki.elonen.NanoHTTPD.Response.IStatus
import java.io.*
import java.net.*
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.charset.Charset
import java.security.KeyStore
import java.text.SimpleDateFormat
import java.util.*
import java.util.logging.Level
import java.util.regex.Pattern
import java.util.zip.GZIPOutputStream
import javax.net.ssl.*
import kotlin.concurrent.Volatile
import kotlin.math.min

import com.xzhao.localhttpserver.LOG
import com.xzhao.localhttpserver.WebFileServer
import kotlin.collections.HashMap

/**
 * A simple, tiny, nicely embeddable HTTP server in Java
 *
 *
 *
 *
 * NanoHTTPD
 *
 *
 * Copyright (c) 2012-2013 by Paul S. Hawke, 2001,2005-2013 by Jarno Elonen,
 * 2010 by Konstantinos Togias
 *
 *
 *
 *
 *
 * **Features + limitations: **
 *
 *
 *
 *  * Only one Java file
 *  * Java 5 compatible
 *  * Released as open source, Modified BSD licence
 *  * No fixed config files, logging, authorization etc. (Implement yourself if
 * you need them.)
 *  * Supports parameter parsing of GET and POST methods (+ rudimentary PUT
 * support in 1.25)
 *  * Supports both dynamic content and file serving
 *  * Supports file upload (since version 1.2, 2010)
 *  * Supports partial content (streaming)
 *  * Supports ETags
 *  * Never caches anything
 *  * Doesn't limit bandwidth, request time or simultaneous connections
 *  * Default code serves files and shows all HTTP parameters and headers
 *  * File server supports directory listing, index.html and index.htm
 *  * File server supports partial content (streaming)
 *  * File server supports ETags
 *  * File server does the 301 redirection trick for directories without '/'
 *  * File server supports simple skipping for files (continue download)
 *  * File server serves also very long files without memory overhead
 *  * Contains a built-in list of most common MIME types
 *  * All header names are converted to lower case so they don't vary between
 * browsers/clients
 *
 *
 *
 *
 *
 *
 *
 * **How to use: **
 *
 *
 *
 *  * Subclass and implement serve() and embed to your own program
 *
 *
 *
 *
 *
 * See the separate "LICENSE.md" file for the distribution license (Modified BSD
 * licence)
 */
abstract class NanoHTTPD(protected val context: Context?,staticPath:String, val hostname: String?, private val myPort: Int) {
    /**
     * Pluggable strategy for asynchronously executing requests.
     */
    interface AsyncRunner {
        fun closeAll()

        fun closed(clientHandler: ClientHandler)

        fun exec(code: ClientHandler)
    }

    /**
     * The runnable that will be used for every new client connection.
     */
    inner class ClientHandler(private val inputStream: InputStream, private val acceptSocket: Socket) : Runnable {
        fun close() {
            safeClose(this.inputStream)
            safeClose(this.acceptSocket)
        }

        override fun run() {
            var outputStream: OutputStream? = null
            try {
                outputStream = acceptSocket.getOutputStream()
                val tempFileManager =
                    tempFileManagerFactory!!.create()
                val session: HTTPSession = HTTPSession(
                    tempFileManager,
                    this.inputStream, outputStream,
                    acceptSocket.inetAddress
                )
                while (!acceptSocket.isClosed) {
                    session.execute()
                }
            } catch (e: Exception) {
                // When the socket is closed by the client,
                // we throw our own SocketException
                // to break the "keep alive" loop above. If
                // the exception was anything other
                // than the expected SocketException OR a
                // SocketTimeoutException, print the
                // stacktrace
                if (!(e is SocketException && "NanoHttpd Shutdown" == e.message) && e !is SocketTimeoutException) {
                    LOG.log(Level.SEVERE, "Communication with the client broken, or an bug in the handler code ：",e.message, e.stackTraceToString())
                }
            } finally {
                safeClose(outputStream)
                safeClose(this.inputStream)
                safeClose(this.acceptSocket)
                asyncRunner!!.closed(this)
            }
        }
    }

    class Cookie {
        private val n: String
        private val v: String
        private val e: String

        @JvmOverloads
        constructor(name: String, value: String, numDays: Int = 30) {
            this.n = name
            this.v = value
            this.e = getHTTPTime(numDays)
        }

        constructor(name: String, value: String, expires: String) {
            this.n = name
            this.v = value
            this.e = expires
        }

        val hTTPHeader: String
            get() {
                val fmt = "%s=%s; expires=%s"
                return String.format(fmt, this.n, this.v, this.e)
            }

        companion object {
            fun getHTTPTime(days: Int): String {
                val calendar = Calendar.getInstance()
                val dateFormat = SimpleDateFormat("EEE, dd MMM yyyy HH:mm:ss z", Locale.US)
                dateFormat.timeZone = TimeZone.getTimeZone("GMT")
                calendar.add(Calendar.DAY_OF_MONTH, days)
                return dateFormat.format(calendar.time)
            }
        }
    }

    /**
     * Provides rudimentary support for cookies. Doesn't support 'path',
     * 'secure' nor 'httpOnly'. Feel free to improve it and/or add unsupported
     * features.
     *
     * @author LordFokas
     */
    inner class CookieHandler(httpHeaders: Map<String, String?>?) : Iterable<String?> {
        val cookies = HashMap<String, String>()

        private val queue = ArrayList<Cookie>()

        init {
            val raw = httpHeaders!!["cookie"]
            if (raw != null) {
                val tokens = raw.split(";".toRegex()).dropLastWhile { it.isEmpty() }.toTypedArray()
                for (token in tokens) {
                    val data = token.trim { it <= ' ' }.split("=".toRegex()).dropLastWhile { it.isEmpty() }
                        .toTypedArray()
                    if (data.size == 2) {
                        cookies[data[0]] = data[1]
                    }
                }
            }
        }

        /**
         * Set a cookie with an expiration date from a month ago, effectively
         * deleting it on the client side.
         *
         * @param name
         * The cookie name.
         */
        fun delete(name: String) {
            set(name, "-delete-", -30)
        }

        override fun iterator(): Iterator<String> {
            return cookies.keys.iterator()
        }

        /**
         * Read a cookie from the HTTP Headers.
         *
         * @param name
         * The cookie's name.
         * @return The cookie's value if it exists, null otherwise.
         */
        fun read(name: String): String? {
            return cookies[name]
        }

        fun set(cookie: Cookie) {
            queue.add(cookie)
        }

        /**
         * Sets a cookie.
         *
         * @param name
         * The cookie's name.
         * @param value
         * The cookie's value.
         * @param expires
         * How many days until the cookie expires.
         */
        fun set(name: String, value: String, expires: Int) {
            queue.add(Cookie(name, value, Cookie.getHTTPTime(expires)))
        }

        /**
         * Internally used by the webserver to add all queued cookies into the
         * Response's HTTP Headers.
         *
         * @param response
         * The Response object to which headers the queued cookies
         * will be added.
         */
        fun unloadQueue(response: Response) {
            for (cookie in this.queue) {
                response.addHeader("Set-Cookie", cookie.hTTPHeader)
            }
        }
    }

    /**
     * Default threading strategy for NanoHTTPD.
     *
     *
     *
     *
     * By default, the server spawns a new Thread for every incoming request.
     * These are set to *daemon* status, and named according to the request
     * number. The name is useful when profiling the application.
     *
     */
    class DefaultAsyncRunner : AsyncRunner {
        private var requestCount: Long = 0

        private val running: MutableList<ClientHandler> = Collections.synchronizedList(ArrayList())

        /**
         * @return a list with currently running clients.
         */
        fun getRunning(): List<ClientHandler> {
            return running
        }

        override fun closeAll() {
            // copy of the list for concurrency
            for (clientHandler in ArrayList(this.running)) {
                clientHandler.close()
            }
        }

        override fun closed(clientHandler: ClientHandler) {
            running.remove(clientHandler)
        }

        override fun exec(clientHandler: ClientHandler) {
            ++this.requestCount
            val t = Thread(clientHandler)
            t.isDaemon = true
            t.name = "NanoHttpd Request Processor (#" + this.requestCount + ")"
            running.add(clientHandler)
            t.start()
        }
    }

    /**
     * Default strategy for creating and cleaning up temporary files.
     *
     *
     *
     *
     * By default, files are created by `File.createTempFile()` in
     * the directory specified.
     *
     */
    class DefaultTempFile(tempdir: File?) : TempFile {
        private val file: File = File.createTempFile("NanoHTTPD-", "", tempdir)

        private val fstream: OutputStream = FileOutputStream(this.file)

        @Throws(Exception::class)
        override fun delete() {
            safeClose(this.fstream)
            if (!file.delete()) {
                throw Exception("could not delete temporary file: " + file.absolutePath)
            }
        }

        override val name: String
            get() = file.absolutePath

        @Throws(Exception::class)
        override fun open(): OutputStream {
            return this.fstream
        }
    }

    /**
     * Default strategy for creating and cleaning up temporary files.
     *
     *
     *
     *
     * This class stores its files in the standard location (that is, wherever
     * `java.io.tmpdir` points to). Files are added to an internal
     * list, and deleted when no longer needed (that is, when
     * `clear()` is invoked at the end of processing a request).
     *
     */
    class DefaultTempFileManager : TempFileManager {
        private val tmpdir = File(System.getProperty("java.io.tmpdir"))

        private val tempFiles: MutableList<TempFile>

        init {
            if (!tmpdir.exists()) {
                tmpdir.mkdirs()
            }
            this.tempFiles = ArrayList()
        }

        override fun clear() {
            for (file in this.tempFiles) {
                try {
                    file.delete()
                } catch (ignored: Exception) {
                    LOG.log(Level.WARNING, "could not delete file ", ignored)
                }
            }
            tempFiles.clear()
        }

        @Throws(Exception::class)
        override fun createTempFile(filename_hint: String?): TempFile {
            val tempFile = DefaultTempFile(this.tmpdir)
            tempFiles.add(tempFile)
            return tempFile
        }
    }

    /**
     * Default strategy for creating and cleaning up temporary files.
     */
    private inner class DefaultTempFileManagerFactory : TempFileManagerFactory {
        override fun create(): TempFileManager {
            return DefaultTempFileManager()
        }
    }

    /**
     * Creates a normal ServerSocket for TCP connections
     */
    class DefaultServerSocketFactory : ServerSocketFactory {
        @Throws(IOException::class)
        override fun create(): ServerSocket {
            return ServerSocket()
        }
    }

    /**
     * Creates a new SSLServerSocket
     */
    class SecureServerSocketFactory(
        private val sslServerSocketFactory: SSLServerSocketFactory,
        private val sslProtocols: Array<String>?
    ) :
        ServerSocketFactory {
        @Throws(IOException::class)
        override fun create(): ServerSocket? {
            var ss: SSLServerSocket? = null
            ss = sslServerSocketFactory.createServerSocket() as SSLServerSocket
            if (this.sslProtocols != null) {
                ss.enabledProtocols = sslProtocols
            } else {
                ss.enabledProtocols = ss.supportedProtocols
            }
            ss.useClientMode = false
            ss.wantClientAuth = false
            ss.needClientAuth = false
            return ss
        }
    }

    protected class ContentType(val contentTypeHeader: String?) {
        var contentType: String? = null

        private var encoding: String? = null

        var boundary: String? = null

        init {
            if (contentTypeHeader != null) {
                contentType = getDetailFromContentHeader(contentTypeHeader, MIME_PATTERN, "", 1)
                encoding = getDetailFromContentHeader(contentTypeHeader, CHARSET_PATTERN, "utf-8", 2)
            } else {
                contentType = ""
                encoding = "UTF-8"
            }
            boundary = if (MULTIPART_FORM_DATA_HEADER.equals(contentType, ignoreCase = true)) {
                getDetailFromContentHeader(contentTypeHeader, BOUNDARY_PATTERN, null, 2)
            } else {
                null
            }
        }

        private fun getDetailFromContentHeader(
            contentTypeHeader: String?,
            pattern: Pattern,
            defaultValue: String?,
            group: Int
        ): String {
            val matcher = pattern.matcher(contentTypeHeader)
            return if (matcher.find()) matcher.group(group) else defaultValue!!
        }

        fun getEncoding(): String {
            return encoding ?: ASCII_ENCODING
        }

        val isMultipart: Boolean
            get() = MULTIPART_FORM_DATA_HEADER.equals(contentType, ignoreCase = true)

        fun tryUTF8(): ContentType {
            if (encoding == null) {
                return ContentType(this.contentTypeHeader + "; charset=UTF-8")
            }
            return this
        }

        companion object {
            private const val ASCII_ENCODING = "US-ASCII"

            private const val MULTIPART_FORM_DATA_HEADER = "multipart/form-data"

            private const val CONTENT_REGEX = "[ |\t]*([^/^ ^;^,]+/[^ ^;^,]+)"

            private val MIME_PATTERN: Pattern = Pattern.compile(CONTENT_REGEX, Pattern.CASE_INSENSITIVE)

            private const val CHARSET_REGEX = "[ |\t]*(charset)[ |\t]*=[ |\t]*['|\"]?([^\"^'^;^,]*)['|\"]?"

            private val CHARSET_PATTERN: Pattern = Pattern.compile(CHARSET_REGEX, Pattern.CASE_INSENSITIVE)

            private const val BOUNDARY_REGEX = "[ |\t]*(boundary)[ |\t]*=[ |\t]*['|\"]?([^\"^'^;^,]*)['|\"]?"

            private val BOUNDARY_PATTERN: Pattern = Pattern.compile(BOUNDARY_REGEX, Pattern.CASE_INSENSITIVE)
        }
    }

    protected inner class HTTPSession : IHTTPSession {
        private val tempFileManager: TempFileManager

        private val outputStream: OutputStream

        override val inputStream: BufferedInputStream

        private var splitbyte = 0

        private var rlen = 0

        override lateinit var uri: String
            private set

        override var method: Method? = null
            private set
        override var proxy: Boolean=false

        lateinit var _parms: MutableMap<String, MutableList<String>>

        override lateinit var headers: MutableMap<String, String>

        override lateinit var cookies: CookieHandler
            private set

        override var queryParameterString: String? =null
            private set

        override lateinit var remoteIpAddress: String
            private set

        override lateinit var remoteHostName: String
            private set

        private var protocolVersion: String? = null

        constructor(tempFileManager: TempFileManager, inputStream: InputStream?, outputStream: OutputStream) {
            this.tempFileManager = tempFileManager
            this.inputStream = BufferedInputStream(inputStream, Companion.BUFSIZE)
            this.outputStream = outputStream
        }

        constructor(
            tempFileManager: TempFileManager,
            inputStream: InputStream?,
            outputStream: OutputStream,
            inetAddress: InetAddress
        ) {
            this.tempFileManager = tempFileManager
            this.inputStream = BufferedInputStream(inputStream, Companion.BUFSIZE)
            this.outputStream = outputStream
            this.remoteIpAddress =
                if (inetAddress.isLoopbackAddress || inetAddress.isAnyLocalAddress) "127.0.0.1" else inetAddress.hostAddress.toString()
            this.remoteHostName =
                if (inetAddress.isLoopbackAddress || inetAddress.isAnyLocalAddress) "localhost" else inetAddress.hostName.toString()
            this.headers = HashMap()
        }

        /**
         * Decodes the sent headers and loads the data into Key/value pairs
         */
        @Throws(ResponseException::class)
        private fun decodeHeader(
            `in`: BufferedReader,
            pre: MutableMap<String, String?>,
            parms: MutableMap<String, MutableList<String>>?,
            headers: MutableMap<String, String>?
        ) {
            try {
                // Read the request line
                val inLine = `in`.readLine() ?: return

                val st = StringTokenizer(inLine)
                if (!st.hasMoreTokens()) {
                    throw ResponseException(
                        Response.Status.BAD_REQUEST,
                        "BAD REQUEST: Syntax error. Usage: GET /example/file.html"
                    )
                }

                pre["method"] = st.nextToken()

                if (!st.hasMoreTokens()) {
                    throw ResponseException(
                        Response.Status.BAD_REQUEST,
                        "BAD REQUEST: Missing URI. Usage: GET /example/file.html"
                    )
                }

                var uri = st.nextToken()

                // Decode parameters from the URI
                val qmi = uri!!.indexOf('?')
                if (qmi >= 0) {
                    decodeParms(uri.substring(qmi + 1), parms)
                    uri = decodePercent(uri.substring(0, qmi))
                } else {
                    uri = decodePercent(uri)
                }

                // If there's another token, its protocol version,
                // followed by HTTP headers.
                // NOTE: this now forces header names lower case since they are
                // case insensitive and vary by client.
                if (st.hasMoreTokens()) {
                    protocolVersion = st.nextToken()
                } else {
                    protocolVersion = "HTTP/1.1"
                    LOG.log(Level.FINE, "no protocol version specified, strange. Assuming HTTP/1.1.")
                }
                var line = `in`.readLine()
                while (line != null && !line.trim { it <= ' ' }.isEmpty()) {
                    val p = line.indexOf(':')
                    if (p >= 0) {
                        headers!![line.substring(0, p).trim { it <= ' ' }.lowercase()] =
                            line.substring(p + 1).trim { it <= ' ' }
                    }
                    line = `in`.readLine()
                }

                pre["uri"] = uri
            } catch (ioe: IOException) {
                LOG.severe(ioe.message,ioe.stackTraceToString())
                throw ResponseException(
                    Response.Status.INTERNAL_ERROR,
                    "SERVER INTERNAL ERROR: IOException: " + ioe.message,
                    ioe
                )
            }
        }

        /**
         * Decodes the Multipart Body data and put it into Key/Value pairs.
         */
        @Throws(ResponseException::class)
        private fun decodeMultipartFormData(
            contentType: ContentType,
            fbuf: ByteBuffer?,
            parms: MutableMap<String, MutableList<String>>?,
            files: MutableMap<String, String>
        ) {
            var pcount = 0
            try {
                val boundaryIdxs = getBoundaryPositions(fbuf, contentType.boundary!!.toByteArray())
                if (boundaryIdxs.size < 2) {
                    throw ResponseException(
                        Response.Status.BAD_REQUEST,
                        "BAD REQUEST: Content type is multipart/form-data but contains less than two boundary strings."
                    )
                }

                val partHeaderBuff = ByteArray(Companion.MAX_HEADER_SIZE)
                for (boundaryIdx in 0 until boundaryIdxs.size - 1) {
                    fbuf!!.position(boundaryIdxs[boundaryIdx])
                    val len =
                        if ((fbuf.remaining() < Companion.MAX_HEADER_SIZE)) fbuf.remaining() else Companion.MAX_HEADER_SIZE
                    fbuf[partHeaderBuff, 0, len]
                    val `in` =
                        BufferedReader(
                            InputStreamReader(
                                ByteArrayInputStream(partHeaderBuff, 0, len),
                                Charset.forName(contentType.getEncoding())
                            ), len
                        )

                    var headerLines = 0
                    // First line is boundary string
                    var mpline = `in`.readLine()
                    headerLines++
                    if (mpline == null || !mpline.contains(contentType.boundary!!)) {
                        throw ResponseException(
                            Response.Status.BAD_REQUEST,
                            "BAD REQUEST: Content type is multipart/form-data but chunk does not start with boundary."
                        )
                    }

                    var partName: String? = null
                    var fileName: String? = null
                    var partContentType: String? = null
                    // Parse the reset of the header lines
                    mpline = `in`.readLine()
                    headerLines++
                    while (mpline != null && mpline.trim { it <= ' ' }.length > 0) {
                        var matcher = CONTENT_DISPOSITION_PATTERN.matcher(mpline)
                        if (matcher.matches()) {
                            val attributeString = matcher.group(2)
                            matcher = CONTENT_DISPOSITION_ATTRIBUTE_PATTERN.matcher(attributeString)
                            while (matcher.find()) {
                                val key = matcher.group(1)
                                if ("name".equals(key, ignoreCase = true)) {
                                    partName = matcher.group(2)
                                } else if ("filename".equals(key, ignoreCase = true)) {
                                    fileName = matcher.group(2)
                                    // add these two line to support multiple
                                    // files uploaded using the same field Id
                                    if (!fileName.isEmpty()) {
                                        if (pcount > 0) partName = partName + pcount++.toString()
                                        else pcount++
                                    }
                                }
                            }
                        }
                        matcher = CONTENT_TYPE_PATTERN.matcher(mpline)
                        if (matcher.matches()) {
                            partContentType = matcher.group(2).trim { it <= ' ' }
                        }
                        mpline = `in`.readLine()
                        headerLines++
                    }
                    var partHeaderLength = 0
                    while (headerLines-- > 0) {
                        partHeaderLength = scipOverNewLine(partHeaderBuff, partHeaderLength)
                    }
                    // Read the part data
                    if (partHeaderLength >= len - 4) {
                        throw ResponseException(
                            Response.Status.INTERNAL_ERROR,
                            "Multipart header size exceeds MAX_HEADER_SIZE."
                        )
                    }
                    val partDataStart = boundaryIdxs[boundaryIdx] + partHeaderLength
                    val partDataEnd = boundaryIdxs[boundaryIdx + 1] - 4

                    fbuf.position(partDataStart)

                    var values = parms!![partName]
                    if (values == null) {
                        values = ArrayList()
                        parms[partName!!] = values
                    }

                    if (partContentType == null) {
                        // Read the part into a string
                        val data_bytes = ByteArray(partDataEnd - partDataStart)
                        fbuf[data_bytes]

                        values.add(String(data_bytes, charset(contentType.getEncoding())))
                    } else {
                        // Read it into a file
                        val path = saveTmpFile(fbuf, partDataStart, partDataEnd - partDataStart, fileName)
                        if (!files.containsKey(partName)) {
                            files[partName!!] = path
                        } else {
                            var count = 2
                            while (files.containsKey(partName + count)) {
                                count++
                            }
                            files[partName + count] = path
                        }
                        values.add(fileName!!)
                    }
                }
            } catch (re: ResponseException) {
                throw re
            } catch (e: Exception) {
                throw ResponseException(Response.Status.INTERNAL_ERROR, e.toString())
            }
        }

        private fun scipOverNewLine(partHeaderBuff: ByteArray, index: Int): Int {
            var index = index
            while (partHeaderBuff[index] != '\n'.code.toByte()) {
                index++
            }
            return ++index
        }

        /**
         * Decodes parameters in percent-encoded URI-format ( e.g.
         * "name=Jack%20Daniels&pass=Single%20Malt" ) and adds them to given
         * Map.
         */
        private fun decodeParms(parms: String?, p: MutableMap<String, MutableList<String>>?) {
            if (parms == null) {
                this.queryParameterString = ""
                return
            }

            this.queryParameterString = parms
            val st = StringTokenizer(parms, "&")
            while (st.hasMoreTokens()) {
                val e = st.nextToken()
                val sep = e.indexOf('=')
                var key: String? = null
                var value: String? = null

                if (sep >= 0) {
                    key = decodePercent(e.substring(0, sep))!!.trim { it <= ' ' }
                    value = decodePercent(e.substring(sep + 1))
                } else {
                    key = decodePercent(e)!!.trim { it <= ' ' }
                    value = ""
                }

                var values = p!![key]
                if (values == null) {
                    values = ArrayList()
                    p[key] = values
                }

                values.add(value!!)
            }
        }

        @Throws(IOException::class)
        override fun execute() {
            var r: Response? = null
            try {
                // Read the first 8192 bytes.
                // The full header should fit in here.
                // Apache's default header limit is 8KB.
                // Do NOT assume that a single read will get the entire header
                // at once!
                val buf = ByteArray(Companion.BUFSIZE)
                this.splitbyte = 0
                this.rlen = 0

                var read = -1
                inputStream.mark(Companion.BUFSIZE)
                try {
                    read = inputStream.read(buf, 0, Companion.BUFSIZE)
                } catch (e: SSLException) {
                    throw e
                } catch (e: IOException) {
                    safeClose(this.inputStream)
                    safeClose(this.outputStream)
                    throw SocketException("NanoHttpd Shutdown")
                }
                if (read == -1) {
                    // socket was been closed
                    safeClose(this.inputStream)
                    safeClose(this.outputStream)
                    throw SocketException("NanoHttpd Shutdown")
                }
                while (read > 0) {
                    this.rlen += read
                    this.splitbyte = findHeaderEnd(buf, this.rlen)
                    if (this.splitbyte > 0) {
                        break
                    }
                    read = inputStream.read(buf, this.rlen, Companion.BUFSIZE - this.rlen)
                }

                if (this.splitbyte < this.rlen) {
                    inputStream.reset()
                    inputStream.skip(splitbyte.toLong())
                }

                this._parms = HashMap()
                if (null == this.headers) {
                    this.headers = HashMap()
                } else {
                    headers!!.clear()
                }

                // Create a BufferedReader for parsing the header.
                val hin = BufferedReader(InputStreamReader(ByteArrayInputStream(buf, 0, this.rlen)))

                // Decode the header into parms and header java properties
                val pre: MutableMap<String, String?> = HashMap()
                decodeHeader(hin, pre, this._parms, this.headers)

                if (null != this.remoteIpAddress) {
                    headers!!["remote-addr"] = this.remoteIpAddress!!
                    headers!!["http-client-ip"] = this.remoteIpAddress!!
                }

                this.method = Method.lookup(pre["method"])
                if (this.method == null) {
                    throw ResponseException(
                        Response.Status.BAD_REQUEST,
                        "BAD REQUEST: Syntax error. HTTP verb " + pre["method"] + " unhandled."
                    )
                }

                this.uri = pre["uri"]!!

                this.cookies = CookieHandler(this.headers)

                val connection = headers["connection"]
                val keepAlive =
                    "HTTP/1.1" == protocolVersion && (connection == null || !connection.matches("(?i).*close.*".toRegex()))

                // Ok, now do the serve()

                // TODO: long body_size = getBodySize();
                // TODO: long pos_before_serve = this.inputStream.totalRead()
                // (requires implementation for totalRead())
                r = serve(this)

                // TODO: this.inputStream.skip(body_size -
                // (this.inputStream.totalRead() - pos_before_serve))
                if (r == null) {
                    throw ResponseException(
                        Response.Status.INTERNAL_ERROR,
                        "SERVER INTERNAL ERROR: Serve() returned a null response."
                    )
                } else {
                    val acceptEncoding = headers["accept-encoding"]
                    cookies.unloadQueue(r)
                    r.requestMethod = method
                    r.setGzipEncoding(!proxy && useGzipWhenAccepted(r) && acceptEncoding != null && acceptEncoding.contains("gzip"))
                    r.setKeepAlive(keepAlive)
                    r.send(this.outputStream)
                }
                if (!keepAlive || r.isCloseConnection) {
                    throw SocketException("NanoHttpd Shutdown")
                }
            } catch (e: SocketException) {
                // throw it out to close socket object (finalAccept)
                throw e
            } catch (ste: SocketTimeoutException) {
                // treat socket timeouts the same way we treat socket exceptions
                // i.e. close the stream & finalAccept object by throwing the
                // exception up the call stack.
                throw ste
            } catch (ssle: SSLException) {
                LOG.severe(ssle.message,ssle.stackTraceToString())
                val resp = newFixedLengthResponse(
                    Response.Status.INTERNAL_ERROR,
                    MIME_PLAINTEXT,
                    "SSL PROTOCOL FAILURE: " + ssle.message
                )
                resp.send(this.outputStream)
                safeClose(this.outputStream)
            } catch (ioe: IOException) {
                LOG.severe(ioe.message,ioe.stackTraceToString())
                val resp = newFixedLengthResponse(
                    Response.Status.INTERNAL_ERROR,
                    MIME_PLAINTEXT,
                    "SERVER INTERNAL ERROR: IOException: " + ioe.message
                )
                resp.send(this.outputStream)
                safeClose(this.outputStream)
            } catch (re: ResponseException) {
                LOG.severe(re.message,re.stackTraceToString())
                val resp = newFixedLengthResponse(
                    re.status, MIME_PLAINTEXT, re.message
                )
                resp.send(this.outputStream)
                safeClose(this.outputStream)
            } finally {
                safeClose(r)
                tempFileManager.clear()
            }
        }

        /**
         * Find byte index separating header from body. It must be the last byte
         * of the first two sequential new lines.
         */
        private fun findHeaderEnd(buf: ByteArray, rlen: Int): Int {
            var splitbyte = 0
            while (splitbyte + 1 < rlen) {
                // RFC2616

                if (buf[splitbyte] == '\r'.code.toByte() && buf[splitbyte + 1] == '\n'.code.toByte() && splitbyte + 3 < rlen && buf[splitbyte + 2] == '\r'.code.toByte() && buf[splitbyte + 3] == '\n'.code.toByte()) {
                    return splitbyte + 4
                }

                // tolerance
                if (buf[splitbyte] == '\n'.code.toByte() && buf[splitbyte + 1] == '\n'.code.toByte()) {
                    return splitbyte + 2
                }
                splitbyte++
            }
            return 0
        }

        /**
         * Find the byte positions where multipart boundaries start. This reads
         * a large block at a time and uses a temporary buffer to optimize
         * (memory mapped) file access.
         */
        private fun getBoundaryPositions(b: ByteBuffer?, boundary: ByteArray): IntArray {
            var res = IntArray(0)
            if (b!!.remaining() < boundary.size) {
                return res
            }

            var search_window_pos = 0
            val search_window = ByteArray(4 * 1024 + boundary.size)

            val first_fill = if ((b.remaining() < search_window.size)) b.remaining() else search_window.size
            b[search_window, 0, first_fill]
            var new_bytes = first_fill - boundary.size

            do {
                // Search the search_window
                for (j in 0 until new_bytes) {
                    for (i in boundary.indices) {
                        if (search_window[j + i] != boundary[i]) break
                        if (i == boundary.size - 1) {
                            // Match found, add it to results
                            val new_res = IntArray(res.size + 1)
                            System.arraycopy(res, 0, new_res, 0, res.size)
                            new_res[res.size] = search_window_pos + j
                            res = new_res
                        }
                    }
                }
                search_window_pos += new_bytes

                // Copy the end of the buffer to the start
                System.arraycopy(search_window, search_window.size - boundary.size, search_window, 0, boundary.size)

                // Refill search_window
                new_bytes = search_window.size - boundary.size
                new_bytes = if ((b.remaining() < new_bytes)) b.remaining() else new_bytes
                b[search_window, boundary.size, new_bytes]
            } while (new_bytes > 0)
            return res
        }

        @Deprecated("use {@link #getParameters()} instead.")
        override fun getParms(): MutableMap<String, String?> {
            val result: MutableMap<String, String?> = HashMap()
            for (key in _parms!!.keys) {
                result[key] = _parms!![key]!![0]
            }

            return result
        }

        override fun getParameters(): MutableMap<String, MutableList<String>> {
            return this._parms
        }

        private val tmpBucket: RandomAccessFile
            get() {
                try {
                    val tempFile = tempFileManager.createTempFile(null)
                    return RandomAccessFile(tempFile.name, "rw")
                } catch (e: Exception) {
                    throw Error(e) // we won't recover, so throw an error
                }
            }

        val bodySize: Long
            /**
             * Deduce body length in bytes. Either from "content-length" header or
             * read bytes.
             */
            get() {
                if (headers!!.containsKey("content-length")) {
                    return headers!!["content-length"]!!.toLong()
                } else if (this.splitbyte < this.rlen) {
                    return (rlen - this.splitbyte).toLong()
                }
                return 0
            }

        @Throws(IOException::class, ResponseException::class)
        override fun parseBody(): MutableMap<String, String> {
            val files:MutableMap<String, String> =HashMap()
            var randomAccessFile: RandomAccessFile? = null
            try {
                var size = bodySize
                var baos: ByteArrayOutputStream? = null
                var requestDataOutput: DataOutput? = null

                // Store the request in memory or a file, depending on size
                if (size < Companion.MEMORY_STORE_LIMIT) {
                    baos = ByteArrayOutputStream()
                    requestDataOutput = DataOutputStream(baos)
                } else {
                    randomAccessFile = tmpBucket
                    requestDataOutput = randomAccessFile
                }

                // Read all the body and write it to request_data_output
                val buf = ByteArray(Companion.REQUEST_BUFFER_LEN)
                while (this.rlen >= 0 && size > 0) {
                    this.rlen = inputStream.read(
                        buf, 0,
                        min(size.toDouble(), Companion.REQUEST_BUFFER_LEN.toDouble())
                            .toInt()
                    )
                    size -= rlen.toLong()
                    if (this.rlen > 0) {
                        requestDataOutput.write(buf, 0, this.rlen)
                    }
                }

                var fbuf: ByteBuffer? = null
                if (baos != null) {
                    fbuf = ByteBuffer.wrap(baos.toByteArray(), 0, baos.size())
                } else {
                    fbuf = randomAccessFile!!.channel.map(FileChannel.MapMode.READ_ONLY, 0, randomAccessFile.length())
                    randomAccessFile.seek(0)
                }

                // If the method is POST, there may be parameters
                // in data section, too, read it:
                if (Method.POST == this.method) {
                    val contentType = ContentType(
                        headers["content-type"]
                    )
                    if (contentType.isMultipart) {
                        val boundary = contentType.boundary
                            ?: throw ResponseException(
                                Response.Status.BAD_REQUEST,
                                "BAD REQUEST: Content type is multipart/form-data but boundary missing. Usage: GET /example/file.html"
                            )
                        decodeMultipartFormData(contentType, fbuf, this._parms, files)
                    } else {
                        val postBytes = ByteArray(fbuf!!.remaining())
                        fbuf[postBytes]
                        val postLine = String(postBytes, charset(contentType.getEncoding())).trim { it <= ' ' }
                        // Handle application/x-www-form-urlencoded
                        if ("application/x-www-form-urlencoded".equals(contentType.contentType, ignoreCase = true)) {
                            decodeParms(postLine, this._parms)
                        } else if (postLine.length != 0) {
                            // Special case for raw POST data => create a
                            // special files entry "postData" with raw content
                            // data
                            files["postData"] = postLine
                        }
                    }
                } else if (Method.PUT == this.method) {
                    files["content"] = saveTmpFile(fbuf, 0, fbuf!!.limit(), null)
                }
            } finally {
                safeClose(randomAccessFile)
            }
            return files
        }

        /**
         * Retrieves the content of a sent file and saves it to a temporary
         * file. The full path to the saved file is returned.
         */
        private fun saveTmpFile(b: ByteBuffer?, offset: Int, len: Int, filename_hint: String?): String {
            var path = ""
            if (len > 0) {
                var fileOutputStream: FileOutputStream? = null
                try {
                    val tempFile = tempFileManager.createTempFile(filename_hint)
                    val src = b!!.duplicate()
                    fileOutputStream = FileOutputStream(tempFile.name)
                    val dest = fileOutputStream.channel
                    src.position(offset).limit(offset + len)
                    dest.write(src.slice())
                    path = tempFile.name
                } catch (e: Exception) { // Catch exception if any
                    throw Error(e) // we won't recover, so throw an error
                } finally {
                    safeClose(fileOutputStream)
                }
            }
            return path
        }
    }

    /**
     * Handles one session, i.e. parses the HTTP request and returns the
     * response.
     */
    interface IHTTPSession {
        @Throws(IOException::class)
        fun execute()

        /**
         * @return the path part of the URL.
         */
        val uri: String

        val cookies: CookieHandler

        val headers: MutableMap<String, String>

        val method: Method?
        var proxy:Boolean

        /**
         * Get the remote ip address of the requester.
         *
         * @return the IP address.
         */
        val remoteIpAddress: String

        /**
         * Get the remote hostname of the requester.
         *
         * @return the hostname.
         */
        val remoteHostName: String

        val inputStream: InputStream?

        val queryParameterString: String?

        @Deprecated("use {@link #getParameters()} instead.")
        fun getParms(): MutableMap<String, String?>

        fun getParameters(): MutableMap<String, MutableList<String>>

        /**
         * Adds the files in the request body to the files map.
         *
         * @param files
         * map to modify
         */
        @Throws(IOException::class, ResponseException::class)
        fun parseBody():MutableMap<String, String>
    }

    /**
     * HTTP Request methods, with the ability to decode a `String`
     * back to its enum value.
     */
    enum class Method {
        GET,
        PUT,
        POST,
        DELETE,
        HEAD,
        OPTIONS,
        TRACE,
        CONNECT,
        PATCH,
        PROPFIND,
        PROPPATCH,
        MKCOL,
        MOVE,
        COPY,
        LOCK,
        UNLOCK,
        REQUEST;

        companion object {
            fun lookup(method: String?): Method? {
                if (method == null) return null

                return try {
                    valueOf(method)
                } catch (e: IllegalArgumentException) {
                    // TODO: Log it?
                    null
                }
            }
        }
    }

    /**
     * HTTP response. Return one of these from serve().
     */
    class Response(
        /**
         * HTTP status code after processing, e.g. "200 OK", Status.OK
         */
        var status: IStatus?,
        /**
         * MIME type of content, e.g. "text/html"
         */
        var mimeType: String?, data: InputStream?, totalBytes: Long
    ) :
        Closeable {
        interface IStatus {
            val info: String

            val requestStatus: Int

            fun getDescription():String
        }

        /**
         * Some HTTP response status codes
         */
        enum class Status(override val requestStatus: Int, override val info: String) : IStatus {
            SWITCH_PROTOCOL(101, "Switching Protocols"),

            OK(200, "OK"),
            CREATED(201, "Created"),
            ACCEPTED(202, "Accepted"),
            NO_CONTENT(204, "No Content"),
            PARTIAL_CONTENT(206, "Partial Content"),
            MULTI_STATUS(207, "Multi-Status"),

            REDIRECT(301, "Moved Permanently"),

            /**
             * Many user agents mishandle 302 in ways that violate the RFC1945
             * spec (i.e., redirect a POST to a GET). 303 and 307 were added in
             * RFC2616 to address this. You should prefer 303 and 307 unless the
             * calling user agent does not support 303 and 307 functionality
             */
            @Deprecated("")
            FOUND(302, "Found"),
            REDIRECT_SEE_OTHER(303, "See Other"),
            NOT_MODIFIED(304, "Not Modified"),
            TEMPORARY_REDIRECT(307, "Temporary Redirect"),

            BAD_REQUEST(400, "Bad Request"),
            UNAUTHORIZED(401, "Unauthorized"),
            FORBIDDEN(403, "Forbidden"),
            NOT_FOUND(404, "Not Found"),
            METHOD_NOT_ALLOWED(405, "Method Not Allowed"),
            NOT_ACCEPTABLE(406, "Not Acceptable"),
            REQUEST_TIMEOUT(408, "Request Timeout"),
            CONFLICT(409, "Conflict"),
            GONE(410, "Gone"),
            LENGTH_REQUIRED(411, "Length Required"),
            PRECONDITION_FAILED(412, "Precondition Failed"),
            PAYLOAD_TOO_LARGE(413, "Payload Too Large"),
            UNSUPPORTED_MEDIA_TYPE(415, "Unsupported Media Type"),
            RANGE_NOT_SATISFIABLE(416, "Requested Range Not Satisfiable"),
            EXPECTATION_FAILED(417, "Expectation Failed"),
            TOO_MANY_REQUESTS(429, "Too Many Requests"),

            INTERNAL_ERROR(500, "Internal Server Error"),
            NOT_IMPLEMENTED(501, "Not Implemented"),
            SERVICE_UNAVAILABLE(503, "Service Unavailable"),
            UNSUPPORTED_HTTP_VERSION(505, "HTTP Version Not Supported");

            override fun getDescription(): String {
                return "" + this.requestStatus + " " + this.info
            }

            companion object {
                fun lookup(requestStatus: Int): Status? {
                    for (status in entries) {
                        if (status.requestStatus == requestStatus) {
                            return status
                        }
                    }
                    return null
                }
            }
        }

        /**
         * Output stream that will automatically send every write to the wrapped
         * OutputStream according to chunked transfer:
         * http://www.w3.org/Protocols/rfc2616/rfc2616-sec3.html#sec3.6.1
         */
        private class ChunkedOutputStream(out: OutputStream?) : FilterOutputStream(out) {
            @Throws(IOException::class)
            override fun write(b: Int) {
                val data = byteArrayOf(
                    b.toByte()
                )
                write(data, 0, 1)
            }

            @Throws(IOException::class)
            override fun write(b: ByteArray) {
                write(b, 0, b.size)
            }

            @Throws(IOException::class)
            override fun write(b: ByteArray, off: Int, len: Int) {
                if (len == 0) return
                out.write(String.format("%x\r\n", len).toByteArray())
                out.write(b, off, len)
                out.write("\r\n".toByteArray())
            }

            @Throws(IOException::class)
            fun finish() {
                out.write("0\r\n\r\n".toByteArray())
            }
        }

        /**
         * Data of the response, may be null.
         */
        var data: InputStream? = null

        private var contentLength: Long = 0

        /**
         * Headers for the HTTP response. Use addHeader() to add lines. the
         * lowercase map is automatically kept up to date.
         */
        val header: MutableMap<String, String> = object : HashMap<String, String>() {
            override fun put(key: String, value: String): String? {
                lowerCaseHeader[key?.lowercase(Locale.getDefault()) ?: key] = value
                return super.put(key, value)
            }
        }

        /**
         * copy of the header map with all the keys lowercase for faster
         * searching.
         */
        private val lowerCaseHeader: MutableMap<String, String> = HashMap()

        /**
         * The request method that spawned this response.
         */
        var requestMethod: Method? = null

        /**
         * Use chunkedTransfer
         */
        private var chunkedTransfer: Boolean

        private var encodeAsGzip = false

        private var keepAlive: Boolean

        /**
         * Creates a fixed length response if totalBytes>=0, otherwise chunked.
         */
        init {
            if (data == null) {
                this.data = ByteArrayInputStream(ByteArray(0))
                this.contentLength = 0L
            } else {
                this.data = data
                this.contentLength = totalBytes
            }
            this.chunkedTransfer = this.contentLength < 0
            keepAlive = true
        }

        @Throws(IOException::class)
        override fun close() {
            if (this.data != null) {
                data!!.close()
            }
        }

        /**
         * Adds given line to the header.
         */
        fun addHeader(name: String, value: String) {
            header[name] = value
        }

        /**
         * Indicate to close the connection after the Response has been sent.
         *
         * @param close
         * `true` to hint connection closing, `false` to
         * let connection be closed by client.
         */
        fun closeConnection(close: Boolean) {
            if (close) header["connection"] = "close"
            else header.remove("connection")
        }

        val isCloseConnection: Boolean
            /**
             * @return `true` if connection is to be closed after this
             * Response has been sent.
             */
            get() = "close" == getHeader("connection")

        fun getHeader(name: String): String? {
            return lowerCaseHeader[name.lowercase(Locale.getDefault())]
        }

        fun setGzipEncoding(encodeAsGzip: Boolean) {
            this.encodeAsGzip = encodeAsGzip
        }

        fun setKeepAlive(useKeepAlive: Boolean) {
            this.keepAlive = useKeepAlive
        }

        /**
         * Sends given response to the socket.
         */
        fun send(outputStream: OutputStream) {
            val gmtFrmt = SimpleDateFormat("E, d MMM yyyy HH:mm:ss 'GMT'", Locale.US)
            gmtFrmt.timeZone = TimeZone.getTimeZone("GMT")

            try {
                if (this.status == null) {
                    throw Error("sendResponse(): Status can't be null.")
                }
                val pw = PrintWriter(
                    BufferedWriter(
                        OutputStreamWriter(
                            outputStream, ContentType(
                                this.mimeType
                            ).getEncoding()
                        )
                    ), false
                )
                pw.append("HTTP/1.1 ").append(status!!.getDescription()).append(" \r\n")
                if (this.mimeType != null) {
                    printHeader(pw, "Content-Type", this.mimeType)
                }
                if (getHeader("date") == null) {
                    printHeader(pw, "Date", gmtFrmt.format(Date()))
                }
                for ((key, value) in this.header) {
                    printHeader(pw, key, value)
                }
                if (getHeader("connection") == null) {
                    printHeader(pw, "Connection", (if (this.keepAlive) "keep-alive" else "close"))
                }
                if (getHeader("content-length") != null) {
                    encodeAsGzip = false
                }
                if (encodeAsGzip) {
                    printHeader(pw, "Content-Encoding", "gzip")
                    setChunkedTransfer(true)
                }
                var pending = if (this.data != null) this.contentLength else 0
                if (this.requestMethod != Method.HEAD && this.chunkedTransfer) {
                    printHeader(pw, "Transfer-Encoding", "chunked")
                } else if (!encodeAsGzip) {
                    pending = sendContentLengthHeaderIfNotAlreadyPresent(pw, pending)
                }
                pw.append("\r\n")
                pw.flush()
                sendBodyWithCorrectTransferAndEncoding(outputStream, pending)
                outputStream.flush()
                safeClose(this.data)
            } catch (ioe: IOException) {
                LOG.log(Level.SEVERE, "Could not send response to the client", ioe)
            }
        }

        protected fun printHeader(pw: PrintWriter, key: String?, value: String?) {
            pw.append(key).append(": ").append(value).append("\r\n")
        }

        protected fun sendContentLengthHeaderIfNotAlreadyPresent(pw: PrintWriter, defaultSize: Long): Long {
            val contentLengthString = getHeader("content-length")
            var size = defaultSize
            if (contentLengthString != null) {
                try {
                    size = contentLengthString.toLong()
                } catch (ex: NumberFormatException) {
                    LOG.severe("content-length was no number $contentLengthString")
                }
            }
            pw.print("Content-Length: $size\r\n")
            return size
        }

        @Throws(IOException::class)
        private fun sendBodyWithCorrectTransferAndEncoding(outputStream: OutputStream, pending: Long) {
            if (this.requestMethod != Method.HEAD && this.chunkedTransfer) {
                val chunkedOutputStream = ChunkedOutputStream(outputStream)
                sendBodyWithCorrectEncoding(chunkedOutputStream, -1)
                chunkedOutputStream.finish()
            } else {
                sendBodyWithCorrectEncoding(outputStream, pending)
            }
        }

        @Throws(IOException::class)
        private fun sendBodyWithCorrectEncoding(outputStream: OutputStream, pending: Long) {
            if (encodeAsGzip) {
                val gzipOutputStream = GZIPOutputStream(outputStream)
                sendBody(gzipOutputStream, -1)
                gzipOutputStream.finish()
            } else {
                sendBody(outputStream, pending)
            }
        }

        /**
         * Sends the body to the specified OutputStream. The pending parameter
         * limits the maximum amounts of bytes sent unless it is -1, in which
         * case everything is sent.
         *
         * @param outputStream
         * the OutputStream to send data to
         * @param pending
         * -1 to send everything, otherwise sets a max limit to the
         * number of bytes sent
         * @throws IOException
         * if something goes wrong while sending the data.
         */
        @Throws(IOException::class)
        private fun sendBody(outputStream: OutputStream, pending: Long) {
            var pending = pending
            val BUFFER_SIZE = (16 * 1024).toLong()
            val buff = ByteArray(BUFFER_SIZE.toInt())
            val sendEverything = pending == -1L
            while (pending > 0 || sendEverything) {
                val bytesToRead = if (sendEverything) BUFFER_SIZE else min(pending.toDouble(), BUFFER_SIZE.toDouble())
                    .toLong()
                val read = data!!.read(buff, 0, bytesToRead.toInt())
                if (read <= 0) {
                    break
                }
                outputStream.write(buff, 0, read)
                if (!sendEverything) {
                    pending -= read.toLong()
                }
            }
        }

        fun setChunkedTransfer(chunkedTransfer: Boolean) {
            this.chunkedTransfer = chunkedTransfer
        }
    }

    class ResponseException : Exception {
        val status: Response.Status

        constructor(status: Response.Status, message: String?) : super(message) {
            this.status = status
        }

        constructor(status: Response.Status, message: String?, e: Exception?) : super(message, e) {
            this.status = status
        }

        companion object {
            private const val serialVersionUID = 6569838532917408380L
        }
    }

    /**
     * The runnable that will be used for the main listening thread.
     */
    inner class ServerRunnable(private val timeout: Int) : Runnable {
        var bindException: IOException? = null

        var hasBinded: Boolean = false

        override fun run() {
            try {
                myServerSocket!!.bind(
                    if (hostname != null) InetSocketAddress(hostname, myPort) else InetSocketAddress(
                        myPort
                    )
                )
                hasBinded = true
            } catch (e: IOException) {
                this.bindException = e
                return
            }
            do {
                try {
                    val finalAccept = myServerSocket!!.accept()
                    if (this.timeout > 0) {
                        finalAccept.soTimeout = timeout
                    }
                    val inputStream = finalAccept.getInputStream()
                    asyncRunner!!.exec(createClientHandler(finalAccept, inputStream))
                } catch (e: IOException) {
                    LOG.log(Level.FINE, "Communication with the client broken", e)
                }
            } while (!myServerSocket!!.isClosed)
        }
    }

    /**
     * A temp file.
     *
     *
     *
     *
     * Temp files are responsible for managing the actual temporary storage and
     * cleaning themselves up when no longer needed.
     *
     */
    interface TempFile {
        @Throws(Exception::class)
        fun delete()

        val name: String

        @Throws(Exception::class)
        fun open(): OutputStream?
    }

    /**
     * Temp file manager.
     *
     *
     *
     *
     * Temp file managers are created 1-to-1 with incoming requests, to create
     * and cleanup temporary files created as a result of handling the request.
     *
     */
    interface TempFileManager {
        fun clear()

        @Throws(Exception::class)
        fun createTempFile(filename_hint: String?): TempFile
    }

    /**
     * Factory to create temp file managers.
     */
    interface TempFileManagerFactory {
        fun create(): TempFileManager
    }

    /**
     * Factory to create ServerSocketFactories.
     */
    interface ServerSocketFactory {
        @Throws(IOException::class)
        fun create(): ServerSocket?
    }

    @Volatile
    private var myServerSocket: ServerSocket? = null

    var serverSocketFactory: ServerSocketFactory = DefaultServerSocketFactory()

    private var myThread: Thread? = null

    /**
     * Pluggable strategy for asynchronously executing requests.
     *
     * @param asyncRunner
     * new strategy for handling threads.
     */
    protected var asyncRunner: AsyncRunner? = null

    /**
     * Pluggable strategy for creating and cleaning up temporary files.
     *
     * @param tempFileManagerFactory
     * new strategy for handling temp files.
     */
    /**
     * Pluggable strategy for creating and cleaning up temporary files.
     */
    var tempFileManagerFactory: TempFileManagerFactory? = null

    init {
        tempFileManagerFactory = DefaultTempFileManagerFactory()
        asyncRunner=DefaultAsyncRunner()
    }

    /**
     * Forcibly closes all connections that are open.
     */
    @Synchronized
    fun closeAllConnections() {
        stop()
    }

    /**
     * create a instance of the client handler, subclasses can return a subclass
     * of the ClientHandler.
     *
     * @param finalAccept
     * the socket the cleint is connected to
     * @param inputStream
     * the input stream
     * @return the client handler
     */
    protected fun createClientHandler(finalAccept: Socket, inputStream: InputStream): ClientHandler {
        return ClientHandler(inputStream, finalAccept)
    }

    /**
     * Instantiate the server runnable, can be overwritten by subclasses to
     * provide a subclass of the ServerRunnable.
     *
     * @param timeout
     * the socet timeout to use.
     * @return the server runnable.
     */
    protected fun createServerRunnable(timeout: Int): ServerRunnable {
        return ServerRunnable(timeout)
    }

    /**
     * @return true if the gzip compression should be used if the client
     * accespts it. Default this option is on for text content and off
     * for everything. Override this for custom semantics.
     */
    protected fun useGzipWhenAccepted(r: Response): Boolean {
        return r.mimeType != null && (r.mimeType!!.lowercase(Locale.getDefault())
            .contains("text/") || r.mimeType!!.lowercase(Locale.getDefault()).contains("/json"))
    }

    val listeningPort: Int
        get() = if (this.myServerSocket == null) -1 else myServerSocket!!.localPort

    val isAlive: Boolean
        get() = wasStarted() && !myServerSocket!!.isClosed && myThread!!.isAlive

    /**
     * Call before start() to serve over HTTPS instead of HTTP
     */
    fun makeSecure(sslServerSocketFactory: SSLServerSocketFactory, sslProtocols: Array<String>?) {
        this.serverSocketFactory = SecureServerSocketFactory(sslServerSocketFactory, sslProtocols)
    }

    /**
     * Override this to customize the server.
     *
     *
     *
     *
     * (By default, this returns a 404 "Not Found" plain text error response.)
     *
     * @param session
     * The HTTP session
     * @return HTTP response, see class Response for details
     */
    open fun serve(session: IHTTPSession): Response {
        var files: MutableMap<String, String>? =null
        val method = session.method
        if (Method.PUT == method || Method.POST == method) {
            try {
                files=session.parseBody()
            } catch (ioe: IOException) {
                LOG.severe(ioe.message,ioe.stackTraceToString())
                return newFixedLengthResponse(
                    Response.Status.INTERNAL_ERROR,
                    MIME_PLAINTEXT,
                    "SERVER INTERNAL ERROR: IOException: " + ioe.message
                )
            } catch (re: ResponseException) {
                LOG.severe(re.message,re.stackTraceToString())
                return newFixedLengthResponse(re.status, MIME_PLAINTEXT, re.message)
            }
        }
        if(files==null){
            files=HashMap()
        }
        val parms = session.getParms()
        parms[QUERY_STRING_PARAMETER] = session.queryParameterString
        return serve(session.uri, method, session.headers, parms, files)
    }

    /**
     * Override this to customize the server.
     *
     *
     *
     *
     * (By default, this returns a 404 "Not Found" plain text error response.)
     *
     * @param uri
     * Percent-decoded URI without parameters, for example
     * "/index.cgi"
     * @param method
     * "GET", "POST" etc.
     * @param parms
     * Parsed, percent decoded parameters from URI and, in case of
     * POST, data.
     * @param headers
     * Header entries, percent decoded
     * @return HTTP response, see class Response for details
     */
    @Deprecated("")
    fun serve(
        uri: String?,
        method: Method?,
        headers: Map<String, String?>?,
        parms: Map<String, String?>?,
        files: Map<String, String>?
    ): Response {
        return newFixedLengthResponse(Response.Status.NOT_FOUND, MIME_PLAINTEXT, "Not Found")
    }

    /**
     * Start the server.
     *
     * @param timeout
     * timeout to use for socket connections.
     * @param daemon
     * start the thread daemon or not.
     * @throws IOException
     * if the socket is in use.
     */
    /**
     * Starts the server (in setDaemon(true) mode).
     */
    /**
     * Start the server.
     *
     * @throws IOException
     * if the socket is in use.
     */
    @JvmOverloads
    @Throws(IOException::class)
    fun start(timeout: Int = SOCKET_READ_TIMEOUT, daemon: Boolean = true) {
        this.myServerSocket = serverSocketFactory.create()
        myServerSocket!!.reuseAddress = true

        val serverRunnable = createServerRunnable(timeout)
        this.myThread = Thread(serverRunnable)
        myThread!!.isDaemon = daemon
        myThread!!.name = "NanoHttpd Main Listener"
        myThread!!.start()
        while (!serverRunnable.hasBinded && serverRunnable.bindException == null) {
            try {
                Thread.sleep(10L)
            } catch (e: Throwable) {
                // on android this may not be allowed, that's why we
                // catch throwable the wait should be very short because we are
                // just waiting for the bind of the socket
            }
        }
        if (serverRunnable.bindException != null) {
            throw serverRunnable.bindException!!
        }
    }

    /**
     * Stop the server.
     */
    fun stop() {
        try {
            safeClose(this.myServerSocket)
            asyncRunner!!.closeAll()
            if (this.myThread != null) {
                myThread!!.join()
            }
        } catch (e: Exception) {
            LOG.log(Level.SEVERE, "Could not stop all connections", e)
        }
    }

    fun wasStarted(): Boolean {
        return this.myServerSocket != null && this.myThread != null
    }
    fun mimeTypes(): Map<String, String>? {
        if (MIME_TYPES == null) {
            MIME_TYPES = HashMap()
            loadMimeTypes(MIME_TYPES, "nanohttpd/default-mimetypes.properties")
            loadMimeTypes(MIME_TYPES, "nanohttpd/mimetypes.properties")
            if (MIME_TYPES!!.isEmpty()) {
                LOG.log(Level.WARNING, "no mime types found in the classpath! please provide mimetypes.properties")
            }
        }
        return MIME_TYPES
    }

    protected var staticMimeFilePath= staticPath
    protected open fun loadMimeTypes(result: MutableMap<String, String>?, resourceName: String) {
        if(this.context==null){
            LOG.log(
                Level.SEVERE,
                "context is null,could not load mimetypes from $resourceName"
            )
            return
        }
        try {
            val properties = Properties()
            var stream: InputStream? = null
            try {
                stream = this.context.assets.open(resourceName)
                properties.load(stream)
            } catch (e: IOException) {
                try{
                    stream = FileInputStream(
                        File(
                            WebFileServer.concatPath(
                                staticMimeFilePath,
                                resourceName
                            )
                        )
                    )
                    properties.load(stream)
                }catch (e: IOException) {
                    LOG.log(
                        Level.SEVERE,
                        "could not load mimetypes from $resourceName", e
                    )
                }
            } finally {
                safeClose(stream)
            }
            val safeProperties: Map<String, String> = properties.mapKeys {
                if(it.key is String){
                    it.key as String
                }else{
                    it.key.toString()
                }
            }
                .mapValues {
                    if(it.value is String){
                        it.value as String
                    }else{
                        it.value.toString()
                    }
                }
            result!!.putAll(safeProperties)
        } catch (e: IOException) {
            LOG.log(
                Level.INFO,
                "no mime types available at $resourceName"
            )
        }
    }

    /**
     * Get MIME type from file name extension, if possible
     *
     * @param uri
     * the string representing a file
     * @return the connected mime/type
     */
    fun getMimeTypeForFile(dot: String): String? {
        var mime: String? = null
        if (dot.isNotEmpty()) {
            mime = mimeTypes()!![dot.lowercase(Locale.getDefault())]
        }
        return mime
    }
    companion object {
        private const val REQUEST_BUFFER_LEN = 512

        private const val MEMORY_STORE_LIMIT = 1024

        const val BUFSIZE: Int = 8192

        const val MAX_HEADER_SIZE: Int = 1024

        private const val CONTENT_DISPOSITION_REGEX = "([ |\t]*Content-Disposition[ |\t]*:)(.*)"

        private val CONTENT_DISPOSITION_PATTERN: Pattern = Pattern.compile(
            CONTENT_DISPOSITION_REGEX, Pattern.CASE_INSENSITIVE
        )

        private const val CONTENT_TYPE_REGEX = "([ |\t]*content-type[ |\t]*:)(.*)"

        private val CONTENT_TYPE_PATTERN: Pattern = Pattern.compile(CONTENT_TYPE_REGEX, Pattern.CASE_INSENSITIVE)

        private const val CONTENT_DISPOSITION_ATTRIBUTE_REGEX =
            "[ |\t]*([a-zA-Z]*)[ |\t]*=[ |\t]*['|\"]([^\"^']*)['|\"]"

        private val CONTENT_DISPOSITION_ATTRIBUTE_PATTERN: Pattern = Pattern.compile(
            CONTENT_DISPOSITION_ATTRIBUTE_REGEX
        )

        /**
         * Maximum time to wait on Socket.getInputStream().read() (in milliseconds)
         * This is required as the Keep-Alive HTTP connections would otherwise block
         * the socket reading thread forever (or as long the browser is open).
         */
        const val SOCKET_READ_TIMEOUT: Int = 5000

        /**
         * Common MIME type for dynamic content: plain text
         */
        const val MIME_PLAINTEXT: String = "text/plain"

        /**
         * Common MIME type for dynamic content: html
         */
        const val MIME_HTML: String = "text/html"

        /**
         * Pseudo-Parameter to use to store the actual query string in the
         * parameters map for later re-processing.
         */
        private const val QUERY_STRING_PARAMETER = "NanoHttpd.QUERY_STRING"

        /**
         * Hashtable mapping (String)FILENAME_EXTENSION -> (String)MIME_TYPE
         */
        protected var MIME_TYPES: MutableMap<String, String>? = null

        /**
         * Creates an SSLSocketFactory for HTTPS. Pass a loaded KeyStore and an
         * array of loaded KeyManagers. These objects must properly
         * loaded/initialized by the caller.
         */
        @Throws(IOException::class)
        fun makeSSLSocketFactory(loadedKeyStore: KeyStore?, keyManagers: Array<KeyManager?>?): SSLServerSocketFactory? {
            var res: SSLServerSocketFactory? = null
            try {
                val trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
                trustManagerFactory.init(loadedKeyStore)
                val ctx = SSLContext.getInstance("TLS")
                ctx.init(keyManagers, trustManagerFactory.trustManagers, null)
                res = ctx.serverSocketFactory
            } catch (e: Exception) {
                throw IOException(e.message)
            }
            return res
        }

        /**
         * Creates an SSLSocketFactory for HTTPS. Pass a loaded KeyStore and a
         * loaded KeyManagerFactory. These objects must properly loaded/initialized
         * by the caller.
         */
        @Throws(IOException::class)
        fun makeSSLSocketFactory(
            loadedKeyStore: KeyStore?,
            loadedKeyFactory: KeyManagerFactory
        ): SSLServerSocketFactory? {
            try {
                return makeSSLSocketFactory(loadedKeyStore, loadedKeyFactory.keyManagers)
            } catch (e: Exception) {
                throw IOException(e.message)
            }
        }

        /**
         * Creates an SSLSocketFactory for HTTPS. Pass a KeyStore resource with your
         * certificate and passphrase
         */
        @Throws(IOException::class)
        fun makeSSLSocketFactory(
            keyAndTrustStoreClasspathPath: String,
            passphrase: CharArray?
        ): SSLServerSocketFactory? {
            try {
                val keystore = KeyStore.getInstance(KeyStore.getDefaultType())
                val keystoreStream = NanoHTTPD::class.java.getResourceAsStream(keyAndTrustStoreClasspathPath)
                    ?: throw IOException("Unable to load keystore from classpath: $keyAndTrustStoreClasspathPath")

                keystore.load(keystoreStream, passphrase)
                val keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm())
                keyManagerFactory.init(keystore, passphrase)
                return makeSSLSocketFactory(keystore, keyManagerFactory)
            } catch (e: Exception) {
                throw IOException(e.message)
            }
        }

        fun safeClose(closeable: Any?) {
            try {
                if (closeable != null) {
                    if (closeable is Closeable) {
                        closeable.close()
                    } else if (closeable is Socket) {
                        closeable.close()
                    } else if (closeable is ServerSocket) {
                        closeable.close()
                    } else {
                        throw IllegalArgumentException("Unknown object to close")
                    }
                }
            } catch (e: IOException) {
                LOG.log(Level.SEVERE, "Could not close", e)
            }
        }

        // -------------------------------------------------------------------------------
        // //
        //
        // Threading Strategy.
        //
        // -------------------------------------------------------------------------------
        // //

        /**
         * Decode parameters from a URL, handing the case where a single parameter
         * name might have been supplied several times, by return lists of values.
         * In general these lists will contain a single element.
         *
         * @param parms
         * original **NanoHTTPD** parameters values, as passed to the
         * `serve()` method.
         * @return a map of `String` (parameter name) to
         * `List<String>` (a list of the values supplied).
         */
        protected fun decodeParameters(parms: Map<String?, String?>): Map<String, MutableList<String>> {
            return decodeParameters(parms[QUERY_STRING_PARAMETER])
        }

        // -------------------------------------------------------------------------------
        // //
        /**
         * Decode parameters from a URL, handing the case where a single parameter
         * name might have been supplied several times, by return lists of values.
         * In general these lists will contain a single element.
         *
         * @param queryString
         * a query string pulled from the URL.
         * @return a map of `String` (parameter name) to
         * `List<String>` (a list of the values supplied).
         */
        protected fun decodeParameters(queryString: String?): Map<String, MutableList<String>> {
            val parms: MutableMap<String, MutableList<String>> = HashMap()
            if (queryString != null) {
                val st = StringTokenizer(queryString, "&")
                while (st.hasMoreTokens()) {
                    val e = st.nextToken()
                    val sep = e.indexOf('=')
                    val propertyName = if (sep >= 0) decodePercent(e.substring(0, sep))!!
                        .trim { it <= ' ' } else decodePercent(e)!!.trim { it <= ' ' }
                    if (!parms.containsKey(propertyName)) {
                        parms[propertyName] = ArrayList()
                    }
                    val propertyValue = if (sep >= 0) decodePercent(e.substring(sep + 1)) else null
                    if (propertyValue != null) {
                        parms[propertyName]!!.add(propertyValue)
                    }
                }
            }
            return parms
        }

        /**
         * Decode percent encoded `String` values.
         *
         * @param str
         * the percent encoded `String`
         * @return expanded form of the input, for example "foo%20bar" becomes
         * "foo bar"
         */
        protected fun decodePercent(str: String?): String? {
            var decoded: String? = null
            try {
                decoded = URLDecoder.decode(str, "UTF8")
            } catch (ignored: UnsupportedEncodingException) {
                LOG.log(Level.WARNING, "Encoding not supported, ignored", ignored)
            }
            return decoded
        }

        /**
         * Create a response with unknown length (using HTTP 1.1 chunking).
         */
        fun newChunkedResponse(status: IStatus?, mimeType: String?, data: InputStream?): Response {
            return Response(status, mimeType, data, -1)
        }

        /**
         * Create a response with known length.
         */
        fun newFixedLengthResponse(
            status: IStatus?,
            mimeType: String?,
            data: InputStream?,
            totalBytes: Long
        ): Response {
            return Response(status, mimeType, data, totalBytes)
        }

        /**
         * Create a text response with known length.
         */
        fun newFixedLengthResponse(status: IStatus?, mimeType: String?, txt: String?): Response {
            var contentType = ContentType(mimeType)
            if (txt == null) {
                return newFixedLengthResponse(status, mimeType, ByteArrayInputStream(ByteArray(0)), 0)
            } else {
                var bytes: ByteArray
                try {
                    val newEncoder = Charset.forName(contentType.getEncoding()).newEncoder()
                    if (!newEncoder.canEncode(txt)) {
                        contentType = contentType.tryUTF8()
                    }
                    bytes = txt.toByteArray(charset(contentType.getEncoding()))
                } catch (e: UnsupportedEncodingException) {
                    LOG.log(Level.SEVERE, "encoding problem, responding nothing", e)
                    bytes = ByteArray(0)
                }
                return newFixedLengthResponse(
                    status,
                    contentType.contentTypeHeader, ByteArrayInputStream(bytes), bytes.size.toLong()
                )
            }
        }

        /**
         * Create a text response with known length.
         */
        fun newFixedLengthResponse(msg: String?): Response {
            return newFixedLengthResponse(Response.Status.OK, MIME_HTML, msg)
        }
    }
}