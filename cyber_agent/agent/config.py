import os
from pathlib import Path
from dotenv import load_dotenv
from langchain_openai import ChatOpenAI
BASE_DIR = Path(__file__).resolve().parent

load_dotenv()
NSU_TOKEN = os.getenv("NSU_TOKEN")
if not NSU_TOKEN:
    raise RuntimeError(
        "Создайте файл .env в вашей директории и укажите: "
        "NSU_TOKEN='ваш_токен'"
    )

MAX_REVISIONS = 2

llm = ChatOpenAI(
    model="Qwen3.8-27B", 
    api_key=NSU_TOKEN,
    base_url="https://deepcode.ci.nsu.ru/api",
    temperature=0,
    timeout=300,
    max_retries=0,
)

def get_tools():
    from cyber_agent.tools import ALL_TOOLS
    return ALL_TOOLS

llm_tools = llm.bind_tools(get_tools())

def get_name_to_tools():
    from cyber_agent.tools import ALL_TOOLS
    return {t.name: t for t in ALL_TOOLS}

NAME_TOOLS = get_name_to_tools()

def load_prompts() -> dict[str, str]:
    prompts_dir = BASE_DIR / "../prompts"
    return {
        "system": (prompts_dir / "system_prompt.md").read_text(encoding="utf-8"),
        "critic": (prompts_dir / "critic_prompt.md").read_text(encoding="utf-8"),
        "defend": (prompts_dir / "defend_prompt.md").read_text(encoding="utf-8"),
    }