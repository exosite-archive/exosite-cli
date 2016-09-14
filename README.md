# Exosite Murano Command Line Tool (exosite cli)

The tool will upload all resources described in the Solutionfile.json to a solution in your business account. This includes static assets, endpoint definitons, event handlers and modules.

## Requirements

- python 2.7 or later

```
sudo pip install --upgrade exosite
```

If you are running OS X El Capitan, the following may be necessary:

```
sudo pip install --upgrade exosite --ignore-installed six --ignore-installed prompt-toolkit --ignore-installed requests
```


## Usage:
This command will prompt you to input credential data and save it to file '.Solutionfile.secret' for latter use.
```
exosite --init
```

This command will perform upload, the target script/file will be read from config file 'Solutionfile.json'
```
exosite --deploy
 ```

#### Usage:

usage: exosite [-h] [--host [HOST]] [-k] [-p] [-s] [-a] [-e] [-m] [--deploy] [--init] [-v]

#### Arguments:
```
-h, --help            show this help message and exit
--host [HOST]
-k, --insecrue        Ignore SSL
-p, --upload_productid
                      Upload static file
-s, --upload_static   Upload static file
-a, --upload_api      Upload api
-e, --upload_eventhandler
                      Upload event handler
-m, --upload_modules  Upload modules
-c, --update_cors     Update cors configuration
--enable_sn <sn>      Add new serial number
--logs [tail]         Script log information
--read <sn> <alias>   Read data from resource
--write <sn> <alias> <value>
                      Write data to resource
--tree                Listing resources
--watch               Watch for modified files and deploy automatically
--open [product|solution]
                      Open solution/product url in browser
--deploy              Upload all solution configurations
--init                Configure for credential parameters
-v, --version         Show Version number

```
#### Solutionfile.json format:
```
{
  "version": "0.2",
  "default_page": "index.html",
  "file_dir": "public",
  "custom_api": "sample_api.lua",
  "custom_api_hook": "_init",
  "product_spec": {
    "lightbulb": "lightbulb.yaml"
  },
  "modules": {
    "auth": "modules/util.lua",
    "debug": "modules/debug.lua"
  },
  "event_handler": {
    "device": {
      "datapoint": "event_handler/product.lua"
    },
    "timer": {
      "timer": "event_handler/timer.lua"
    }
  }
}
{
  "version": "0.3",
  "default_page": "index.html",
  "assets": "public",
  "routes": "sample_api.lua",
  "routes_hook": "_init",
  "modules": {
    "auth": "modules/util.lua",
    "debug": "modules/debug.lua"
  },
  "services": {
    "device": {
      "datapoint": "event_handler/product.lua"
    },
    "timer": {
      "timer": "event_handler/timer.lua"
    }
  }
  "cors": {
    "origin": ["http://localhost:*"],
    "methods":["get", "post"],
    "expose_headers": ["X-Key"],
    "credentials": true
  }
}
```

#### Custom API file format:

```
--#ENDPOINT <METHOD> <PATH>
SCRIPT_CODE
 ```

where `--#ENDPOINT <METHOD> <PATH>` is also separator between endpoint definitions, for example:

```
--#ENDPOINT GET /keystore/{value}
return Keystore.get({key = request.parameters.value})
--#ENDPOINT POST /user/{email}/lightbulbs
return User.listUserRoleParamValues({
  id = request.user_id,
  role_id = "lightbulb_owner",
  parameter_name = "serialnumber"
})
```
