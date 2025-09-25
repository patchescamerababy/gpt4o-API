# gpt4o-API
一个OpenAI API 兼容服务端程序

## 支持的 API

- `GET /v1/models`: Get model list
- `POST /v1/chat/completions`: Chat API


其中模型固定为gpt-4o-2024-08-06，不需要Bearer，支持发送图片、但不支持Function calling

## 启动说明
 `-h, --help                 Display this help message `
 
 `-p, --port <number>        Specify the port number (default: 80) `
 
 `-c, --charset <charset>    Set output charset: UTF-8 or GBK (default depends on OS) `
 
 `-f, --prefix <prefix>      Set API path prefix, e.g. GPT4 (default: none) `

## 测试示例

#### 对话
 	curl -X POST 'http://127.0.0.1:8080/v1/chat/completions' \
 	--header 'Content-Type: application/json' \
 	--data '{"stream":false,"messages":[{"role":"user","content":"hello"}],"model":"gpt-4o"}'
  

#### 传图：

	curl -X POST http://127.0.0.1:8080/v1/chat/completions \
	 --header 'Content-Type: application/json' \
	 --data '{"messages":[{"role":"user","content":[{"type":"text","text":"What is this"},{"type":"image_url","image_url":{"url":"data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAgAAAAICAYAAADED76LAAAABGdBTUEAALGPC/xhBQAAAEBJREFUGNNjYACCBAWF/yCMzmaACVy4cOG/g4MDWAJEw9hwBTBBZAxXECwtjVUBSBxuDboiFEl0RVglkRUxkAoA6pU6bjl6zpsAAAAASUVORK5CYII="}}]}],"model":"gpt-4o","stream":false}'
