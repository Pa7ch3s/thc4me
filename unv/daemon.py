from fastapi import FastAPI
import uvicorn

app = FastAPI()

@app.get("/health")
def health():
    return {"status": "ok"}

def main():
    uvicorn.run("unv.daemon:app", host="127.0.0.1", port=8000, reload=False)

if __name__ == "__main__":
    main()
