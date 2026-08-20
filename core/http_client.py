import requests


def send_request(method,url,headers=None,query_params=None,json_body=None,form_data=None,cookies=None,timeout=10,proxy=None):
    proxies=get_proxies(proxy)
    try:
      response=requests.request(
          method=method,
          url=url,
          headers=headers,
          params=query_params,
          json=json_body,
          data=form_data,
          cookies=cookies,
          timeout=timeout,
          verify=True,
          allow_redirects=False,
          proxies= proxies 
               
      )
      
    except requests.exceptions.RequestException as e:
        print(f"There was some kind of error: {e}")
        return None
        
    return response

def get_proxies(proxy):
    
    if not proxy:
        return None
    return {
        "http": proxy,
        "https": proxy
    }