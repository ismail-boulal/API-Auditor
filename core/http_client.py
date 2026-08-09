import requests


def send_request(method,url,headers=None,query_params=None,json_body=None,form_data=None,cookies=None,timeout=10):
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
          # proxies= later 
               
      )
      
    except requests.exceptions.RequestException as e:
        print(f"There was some kind of error: {e}")
        return None
        
    return response

