import streamlit as st
import requests
from PIL import Image
from io import BytesIO

BLACKLIST = ["127.0.0.1", "localhost", "169.254.169.254"]

def is_banned(url: str) -> bool:
    return any(badpattern in url for badpattern in BLACKLIST)

st.markdown(
    """
    <style>
    .stApp {
        background-image: url("https://img.magnific.com/premium-photo/texture-old-purple-fabric-has-vintage-dullness-there-is-text-area-background-used-vintage-wallpapers-designsx9_661047-1055.jpg?semt=ais_hybrid");
        background-size: cover;
        background-position: center;
        background-attachment: fixed;
    }
    </style>
    """,
    unsafe_allow_html=True
)

st.title("Просмотр котиков")
st.write("Загружайте кота по ссылке")

if st.button("Показать случайного котика"):
    try:
        r = requests.get("https://cataas.com/cat", timeout=10)
        img = Image.open(BytesIO(r.content))
        st.image(img, caption="Случайный котик")
    except Exception as e:
        st.error(f"Не удалось загрузить котика: {e}")

st.divider()

st.subheader("Загрузить по URL")
url = st.text_input("URL:", placeholder="https://cataas.com/cat")

if st.button("Загрузить"):
    if not url:
        st.warning("Введите URL")
    elif is_banned(url):
        st.error("Запрещенное действие")
    else:
        try:
            r = requests.get(url, timeout=5, allow_redirects=True)
            content_type = r.headers.get("Content-Type", "")

            if content_type.startswith("image/"):
                img = Image.open(BytesIO(r.content))
                st.image(img, caption=f"Загружено: {url}")
            else:
                st.success(f"HTTP {r.status_code} ({content_type})")
                st.code(r.text[:5000])

        except Exception as e:
            st.error(f"Ошибка: {e}")