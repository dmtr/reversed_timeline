var require = {
    baseUrl: '/static',
    shim : {
        "jquery-mousewheel": ["jquery"],
        "bootstrap": { "deps": ['jquery'] }
    },
    paths: {
        "jquery": ["//code.jquery.com/jquery-2.2.0.min", "jquery/jquery.min"],
        "bootstrap":  ["//netdna.bootstrapcdn.com/bootstrap/3.3.6/js/bootstrap.min", "bootstrap/js/bootstrap.min"],
        "ramda": ["//cdnjs.cloudflare.com/ajax/libs/ramda/0.19.1/ramda.min", "ramda.min"],
        "jquery-mousewheel": ["//cdnjs.cloudflare.com/ajax/libs/jquery-mousewheel/3.1.13/jquery.mousewheel.min"]
    }
};
