import os
from langchain.agents import create_agent
from langchain.tools import tool

from langchain_deepseek import ChatDeepSeek
from dotenv import load_dotenv

from tools import ALL_TOOLS


load_dotenv()
NSU_TOKEN = os.getenv("NSU_TOKEN")
if not NSU_TOKEN:
    raise RuntimeError("Создайте файл .env в вашей директории и укажите: NSU_TOKEN='токен Беспалова'")

llm = ChatDeepSeek(
    model="deepseek-ai/DeepSeek-V4-Flash-0731",
    api_key=NSU_TOKEN,
    base_url="https://deepcode.ci.nsu.ru/api",
    temperature=0
)


agent = create_agent(
    model=llm,
    tools=ALL_TOOLS
)

if __name__ == "__main__":
    task = (
        "проверить приложение http://localhost:3000 на уязвимости"
        "проверить IDOR на точке входа  /rest/basket с id=\'1\' и токеном \'test-token-123\'"
    )
    result = agent.invoke({
        "messages": [{"role": "user", "content": task}]
    })

print(result["messages"][-1].content)