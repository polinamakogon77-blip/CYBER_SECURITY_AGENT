import os
from langchain.agents import create_agent
from langchain.tools import tool
from langchain_openai import ChatOpenAI
from dotenv import load_dotenv

load_dotenv()
NSU_TOKEN = os.getenv("NSU_TOKEN")
if not NSU_TOKEN:
    raise RuntimeError("Создайте файл .env в вашей директории и укажите: NSU_TOKEN='токен Беспалова'")

llm = ChatOpenAI(
    model="deepseek-ai/DeepSeek-V4-Flash",
    api_key=NSU_TOKEN,
    base_url="https://deepcode.ci.nsu.ru/api/v1",
    temperature=0,
)

@tool
def get_weather(location: str) -> str:
    """Get current weather for a location."""
    return f"Weather in {location}: Sunny, 12°C"

agent = create_agent(
    model=llm,
    tools=[get_weather],
)

result = agent.invoke({
    "messages": [{"role": "user", "content": "What's the weather in Novosibirsk?"}]
})

print(result["messages"][-1].content)