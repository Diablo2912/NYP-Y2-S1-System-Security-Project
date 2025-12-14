import os

from newsapi import NewsApiClient
from dotenv import load_dotenv

load_dotenv()

def get_featured_articles():
    api_key = os.getenv("NEWS_API_KEY")
    newsapi = NewsApiClient(api_key=api_key)

    try:
        # Fetching agriculture-related news
        response = newsapi.get_everything(
            q="agriculture OR farming OR agritech OR sustainable farming",
            language="en",
            sort_by="publishedAt",
            page_size=5  # Get the latest 5 articles
        )

        if response['status'] == 'ok' and response['articles']:
            return response['articles']
        else:
            print("No articles found or API returned an error:", response)
            return []
    except Exception as e:
        print(f"Error fetching articles: {e}")
        return []