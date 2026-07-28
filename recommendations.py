RECOMMENDATIONS = {


    "Cross Site Scripting (XSS)": {

        "Impact":
        "Attackers can execute malicious scripts in user browsers.",

        "Fixes":[

            "Implement input validation",

            "Use output encoding",

            "Enable Content Security Policy"

        ]

    },


    "SQL Injection": {

        "Impact":
        "Attackers may access or modify database information.",

        "Fixes":[

            "Use prepared statements",

            "Use parameterized queries",

            "Validate user input"

        ]

    },


    "CORS Misconfiguration": {

        "Impact":
        "Unauthorized websites may access sensitive resources.",

        "Fixes":[

            "Restrict allowed origins",

            "Avoid wildcard (*) origins",

            "Configure CORS securely"

        ]

    },


    "Security Misconfiguration": {

        "Impact":
        "Improper configuration may expose sensitive services.",

        "Fixes":[

            "Disable unnecessary services",

            "Update software",

            "Apply secure configurations"

        ]

    },


    "Directory Listing": {

        "Impact":
        "Attackers may view hidden files and directories.",

        "Fixes":[

            "Disable directory browsing",

            "Restrict server permissions"

        ]

    },


    "Open Redirect": {

        "Impact":
        "Attackers may redirect users to malicious websites.",

        "Fixes":[

            "Validate redirect URLs",

            "Use allowlists"

        ]

    },


    "Information Disclosure": {

        "Impact":
        "Sensitive system information may be exposed.",

        "Fixes":[

            "Remove debug information",

            "Hide server banners"

        ]

    },


    "SSRF": {

        "Impact":
        "Attackers may access internal services.",

        "Fixes":[

            "Validate URLs",

            "Restrict outbound requests",

            "Use network filtering"

        ]

    }

}



def get_recommendation(vulnerability):


    return RECOMMENDATIONS.get(

        vulnerability,

        {

            "Impact":
            "No impact information available.",


            "Fixes":[

                "Review security configuration",

                "Apply security best practices"

            ]

        }

    )