## 介绍
本插件仅适用于安卓，可以实现部署一个web页面，并可添加代理路径，或添加自定义处理路径，支持路径参数，如`"/test/{page}/user/{id}/home"`。
下方示例均为uts语言调用，js调用时去除类型声明。
### 开始
通过调用`createServer(port:number,host:string="0.0.0.0"):IWebFileServer`方法创建一个服务器实例

#### 示例：
```typescript
const server:IWebFileServer=createServer(5123,'0.0.0.0')
```
#### 返回值：
`IWebFileServer` 接口定义了一组方法，用于操作和管理 Web 服务器，支持添加资源处理、设置跨域访问、修改静态文件路径等功能。该接口实现了通过 HTTP 服务器提供静态文件服务和处理动态请求的能力。

## IWebFileServer接口方法及说明

### 1. `start()`
启动服务器。

#### 返回值：
`boolean` - 如果服务器启动成功，返回 `true`，否则返回 `false`。

#### 示例：
```typescript
let server:IWebFileServer=createServer(5123,'0.0.0.0')
if (server.start()) {
    console.log('服务器启动成功');
} else {
    console.log('服务器启动失败');
}
```

### 2. `getHostname()`
获取服务器监听的主机名。

#### 返回值：
`string` - 返回监听的主机名。

#### 示例：
```typescript
const hostname = server.getHostname();
console.log('服务器主机名:', hostname);
```

### 3. `getListeningPort()`
获取服务器监听的端口号。

#### 返回值：
`number` - 返回监听的端口号。

#### 示例：
```typescript
const port = server.getListeningPort();
console.log('服务器监听端口:', port);
```

### 4. `isAlive()`
检查服务器是否处于运行状态。

#### 返回值：
`boolean` - 如果服务器运行中，返回 `true`，否则返回 `false`。

#### 示例：
```typescript
if (server.isAlive()) {
    console.log('服务器正在运行');
} else {
    console.log('服务器未运行');
}
```

### 5. `setCors(v: boolean)`
设置服务器是否允许跨域请求。

#### 参数：
- `v` (boolean)：如果为 `true`，服务器将允许跨域访问。

#### 示例：
```typescript
server.setCors(true);  // 允许跨域请求
```

### 6. `stop()`
关闭服务器。

#### 示例：
```typescript
server.stop();  // 停止服务器
```

### 7. `addResourceHandler(method: string, uri: string, handler: IResourceHandler)`
为指定的 URI 添加资源处理器，当定义的资源路径与代理路径重叠时将抛出异常。

#### 参数：
- `method` (string)：HTTP 请求方法，如 `"GET"`、`"POST"` 等。
- `uri` (string)：URI 路径，可以包含路径参数（如 `"/api/{test}/user/{id}"`）。
- `handler` (session:ISession,response:IResponse)=>void：资源处理器回调函数，接收 `session` 和 `response` 两个参数。
+ ISession，IResponse定义查看下方

#### 示例：
```typescript
server.addResourceHandler(MethodType.GET,"/test/{page}/user/{id}/home",
	function(session:ISession,response:IResponse):void{
		//获取路径参数page
		console.log(session.pathVariable["page"])
		//获取路径参数id
		console.log(session.pathVariable["id"])
		//获取请求体
		console.log(session.body)
		//获取请求体解析后的json对象（若content-type为text/json）
		console.log(session.json)
		//获取查询参数
		console.log(session.params)
		//获取请求头
		console.log(session.headers)
		//获取请求cookie
		console.log(session.cookie)
		//设置返回文件
		// response.body_file="/storage/emulated/0/Android/data/包名/apps/__UNI__xxxxx/www/static/assets/nanohttpd/default-mimetypes.properties"
		//设置返回json对象，将自动解析为json字符串
		// response.body_json={a:12,v:{b:"123"}}
		//设置返回字符串
		response.body_text="测试一下"
		//设置返回头
		response.header={"head1":"aaabbb","head2":3242,"head3":{name:"aadd"}}
	})
```
#### Isession，IResponse定义
```typescript
export type ISession={
	/**请求的路径地址*/
	uri:string
	/**
	 * 获取请求查询参数，上传的表单参数也会存储于此，同名参数值存入同一列表
	 */
	params:MutableMap<string,MutableList<String>>
	/**请求的查询参数原字符串*/
	queryParameterString:string|null
	/**请求头*/
	headers:MutableMap<string,string>
	/**请求的方法*/
	method:string
	/**远程主机名*/
	remoteHostName:string
	/**远程ip地址*/
	remoteIpAddress:string
	/**当为POST方法时，此处获取body*/
	body:string|null
	/**当为PUT方法时，此处为存储的文件的临时位置*/
	tempFilePath:string|null
	/**当为POST方法，且content-type为"application/json"，且body不为null时，会自动解析body并存于body字段*/
	json:UTSJSONObject|null
	/** 获取cookie，Map类型，以cookie的name为键 */
	cookie:MutableMap<string,string>
	/**请求的路径参数，为Map类型，值始终为string类型，若需其它类型需自行转换*/
	pathVariable:MutableMap<string,string>
}
export type IResponse={
	/**状态码,默认为OK(200)，可取值参照nanohttpd中Status枚举值*/
	status:number
	/** 当该值不为null时，将读取该路径下文件并返回，路径应为文件的绝对路径，此时body_text、body_json字段将被无视,注意，当文件位于公共存储空间时需申请文件读取权限 */
	body_file:string|null
	/** 当该值不为null时,且body_file为null时，将该值转为json字符串返回，此时body_text字段将被无视 */
	body_json:any|null
	/** 当该值不为null时，且body_file、body_json为null时，将该值作为响应体返回*/
	body_text:string|null
	/**响应的content-type值，为null时自动设置，默认值为null*/
	mimetype:string|null
	/** 响应头，默认值为null*/
	header:UTSJSONObject|null
}

```

### 8. `addProxyPath(uri: string, targetHost: string)`
添加一个代理路径，将请求转发到目标服务器，当定义的代理路径与资源路径重叠时将覆盖资源路径。


#### 参数：
- `uri` (string)：本地服务器的 URI 路径。
- `targetHost` (string)：目标服务器的地址。

#### 示例：
```typescript
//对于该服务器的请求如"/proxy/api/user/get/info"将自动请求"www.proxy.example:12345/user/get/info"并返回响应
server.addProxyPath('/proxy/api', 'http://www.example.com');
```

### 9. `updateStaticFilePathType(staticFilePathType: number)`
更新静态文件的路径类型，路径类型默认为Assets，可选值：Assets,Static,Public。
分别表示应用内部存储空间，应用外部存储空间，公共存储空间。

#### 参数：
- `staticFilePathType` (number)：路径类型，可以是 `StaticPathType.Assets`、`StaticPathType.Static` 或 `StaticPathType.Public`。

#### 示例：
```typescript
server.updateStaticFilePathType(StaticPathType.Static);
```

### 10. `updateStaticFilePath(path: string)`
更新静态资源文件的路径，当前路径类型将影响更新路径的过程。

#### 参数：
- `path` (string)：新的静态文件路径。

#### 示例：
```typescript
server.updateStaticFilePath('assets/static');
```

### 11. `getStaticFilePath()`
获取当前静态资源文件的路径。

#### 返回值：
`string` - 当前静态文件路径，需结合路径类型判断实际文件路径。

#### 示例：
```typescript
const staticFilePath = server.getStaticFilePath();
console.log('静态文件路径:', staticFilePath);
```

### 12. `getStaticFilePathType()`
获取当前静态文件路径的类型。

#### 返回值：
`number` - 静态文件路径类型，值可以是 `0`（Assets）、`1`（Static）、`2`（Public）。

#### 示例：
```typescript
const staticFilePathType = server.getStaticFilePathType();
console.log('静态文件路径类型:', staticFilePathType);
```

### 13. `updateStaticMimeFilePath(path: string)`
更新 Mime 类型配置文件的位置。

#### 参数：
- `path` (string)：Mime 类型文件的路径，应该是父目录路径。

#### 示例：
```typescript
server.updateStaticMimeFilePath('/static/assets/nanohttpd');
```

### 导出方法
#### `setLogLevel(level:number)`
设置服务器自带日志的输出等级

#### 参数：
- `level` (number)：服务器内置日志的输出等级

### 导出类
可用其中的静态属性，方便赋值，插件更新时也可提供更好的兼容性
包含：StaticPathType,MethodType,LogLevel,Status

## 完整uts语言调用演示如下，js调用时需将类型声明去除：
```typescript
<template>
	<view style="height: 100%;">
		<view style="height: 50%;">
			<web-view ref="web" src="http://127.0.0.1:5123"></web-view>
		</view>
		<scroll-view>
			<button @click="refresh_page" class="bt">刷新页面</button>
			<button @click="open_server" class="bt">开启服务器</button>
			<button @click="is_alive" class="bt">是否运行:{{alive}}</button>
			<button @click="get_port" class="bt">获取监听端口:{{port}}</button>
			<button @click="get_host" class="bt">获取监听地址:{{host}}</button>
			<button @click="stop_server" class="bt">关闭服务器</button>
		</scroll-view>
	</view>
</template>

<script>
	import { createServer,IWebFileServer,StaticPathType,MethodType,IResourceHandler,ISession,IResponse,setLogLevel,LogLevel,Status } from "@/uni_modules/xzhao-uts-LocalHttpServer"
	let server:IWebFileServer=createServer(5123,'0.0.0.0')
	export default {
		data() {
			return {
				server:null,
				alive:false,
				port:-1,
				host:''
			}
		},
		onLoad() {
			console.log(server)
			//设置日志等级
			setLogLevel(LogLevel.ALL)
			//更新静态资源路径类型
			server.updateStaticFilePathTypeWithPath(StaticPathType.Static,"assets/static")
			// server.updateStaticFilePath("public")
			console.log("静态资源路径为：",server.getStaticFilePath())
			console.log("静态资源路径类型为：",server.getStaticFilePathType())
			//更新mimetype文件路径
			server.updateStaticMimeFilePath("/storage/emulated/0/Android/data/包名/__UNI__xxxxxx/www/static/assets/mime/")
			//设置允许跨域访问本服务器
			server.setCors(true)
			//添加路径处理
			server.addResourceHandler(MethodType.GET,"/test/{page}/user/{id}/home",
				function(session:ISession,response:IResponse):void{
					console.log(session.pathVariable["page"])
					console.log(session.pathVariable["id"])
					console.log(session.body)
					console.log(session.json)
					console.log(session.params)
					console.log(session.headers)
					console.log(session.cookie)
					// response.body_file="/storage/emulated/0/Android/data/包名/apps/__UNI__xxxxx/www/static/assets/nanohttpd/default-mimetypes.properties"
					// response.body_json={a:12,v:{b:"123"}}
					response.body_text="测试一下"
					response.header={"head1":"aaabbb","head2":3242,"head3":{name:"aadd"}}
					response.status=Status.OK
				})
			//添加代理路径
			server.addProxyPath("/proxy/test/","http://127.0.0.1:12345")
			//测试代理路径
			let targetServer=createServer(12345)
			targetServer.addResourceHandler(MethodType.REQUEST,"/be/proxy",
				function(session:ISession,response:IResponse):void{
					console.log("接收到请求")
					response.body_json={"目标代理服务器":"返回结果","dwad":123123,"89879":["wadad"]}
				})
			targetServer.start()
		},
		methods: {
			refresh_page(){
				let w=this.$refs["web"] as UniWebViewElement
				w.reload()
			},
			open_server(){
				server.start()
			},
			get_host(){
				this.host=server.getHostname()
			},
			get_port(){
				this.port=server.getListeningPort()
			},
			is_alive(){
				this.alive=server.isAlive()
			},
			stop_server(){
				server.stop()
			}
		}
	}
</script>

<style>
	.logo {
		height: 100px;
		width: 100px;
		margin: 100px auto 25px auto;
	}

	.bt {
		font-size: 18px;
		color: #8f8f94;
		text-align: center;
	}
</style>
```