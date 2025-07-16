from newsapi import NewsApiClient


def get_featured_articles():
    api_key = '4e7c5fd299724d639e7d9e42ad933770'
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