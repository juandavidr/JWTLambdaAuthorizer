'use strict';
const jwt = require('jsonwebtoken');
const AWS = require('aws-sdk');
const region = "us-east-1";
const secretName = "integration/jwt";

let userIdentifierKey = '';
let networkId = '';


exports.handler = async function(event, context, callback) {
    console.log('Received event:\n', JSON.stringify(event, null, 2));

    // remove the 'Bearer ' prefix from the auth token
    var token = event.authorizationToken.replace('Bearer ', '');

    //temporal test
    token = await create_access_token();
    // end temporal test
    const policy = create_policy(event['methodArn'], 'principal_id');

    if (event['authorizationToken']) {
        const user_info = auth_token_decode(token);
        console.log(user_info);
        if (user_info) {
            policy.allowAllMethods();
        } else {
            policy.denyAllMethods();
        }
    } else {
        policy.denyAllMethods();
    }
    return callback(null, policy.build());

};

/**
 * TODO: delete method
 * @returns 
 */
const create_access_token = async function() {
    //Returns new JWT Token.
    let secret = await _getPrivateKeyValue();

    let jwt_info = jwt.sign({
        "sub": "ev-connect",
        "exp": Date.now() + 300
    }, secret['partner.api.jwt.token.secret']);
    return jwt_info;
};

class AuthPolicy {
    /** 
     The AWS account id the policy will be generated
    for.This is used to create the method ARNs.
    */
    wsAccountId = '';
    /**
     * The principal used
     * for the policy, this should be a unique identifier
     * for the end user.
     */
    principalId = '';
    /**
     * The policy version used
     * for the evaluation.This should always be '2012-10-17'
     */
    version = '2012-10-17';
    /**
     * The regular expression used to validate resource paths
     * for the policy
     */
    pathRegex = '^[/.a-zA-Z0-9-\*]+$'

    /**
     *  Internal lists of allowed and denied methods.
     * 
     *  These are lists of objects and each object has 2 properties: A resource
     *  ARN and a nullable conditions statement.The build method processes these
     *  lists and generates the approriate statements
     *  for the final policy.
     */
    allowMethods = [];
    denyMethods = [];

    /**
     * The API Gateway API id.By
     * default this is set to '*' 
     */
    restApiId = '*';
    /**
     *  The region where the API is deployed.By
     *  default this is set to '*'
     */
    region = '*';
    /**
     *  The name of the stage used in the policy.By
     *  default this is set to '*'
     */
    stage = '*';
    /**
     * 
     */
    methodArn = '';
    /**
     * 
     * @param {*} principal 
     * @param {*} awsAccountId 
     */
    constructor(principal, awsAccountId) {
        this.awsAccountId = awsAccountId;
        this.principalId = principal;
        this.allowMethods = [];
        this.denyMethods = [];
    }

    httpVerbs = {
        'GET': 'GET',
        'POST': 'POST',
        'PUT': 'PUT',
        'PATCH': 'PATCH',
        'HEAD': 'HEAD',
        'DELETE': 'DELETE',
        'OPTIONS': 'OPTIONS',
        'ALL': '*'
    }

    _addMethod(effect, verb, resource, conditions) {
        /**
         * 
         * Adds a method to the internal lists of allowed or denied methods. Each object in
         * the internal list contains a resource ARN and a condition statement.The condition
         * statement can be null.
         */
        if (verb != '*' && !this.httpVerbs.has(verb)) {
            throw ('Invalid HTTP verb ' + verb + '. Allowed verbs in HttpVerb class');
        }
        if (!resource.match(this.pathRegex)) {
            throw ('Invalid resource path: ' + resource + '. Path should match ' + this.pathRegex);
        }
        if (resource[1] == '/') {
            resource = resource[1];
        }
        // let resourceArn = `arn:aws:execute-api:${this.region}:${this.awsAccountId}:${this.restApiId}/${this.stage}/${verb}/${resource}`;
        let resourceArn = this.methodArn;
        if (effect.toLowerCase() == 'allow') {
            this.allowMethods.push({
                'resourceArn': resourceArn,
                'conditions': conditions
            });

        } else
        if (effect.toLowerCase() == 'deny')
            this.denyMethods.push({
                'resourceArn': resourceArn,
                'conditions': conditions
            });
    }


    _getEmptyStatement(effect) {

        /**
         * Returns an empty statement object prepopulated with the correct action and the
         * desired effect.
         */

        let statement = {
            'Action': 'execute-api:Invoke',
            'Effect': this._camelize(effect),
            'Resource': []
        };

        return statement;
    }

    _camelize(str) {
        return (" " + str).toLowerCase().replace(/[^a-zA-Z0-9]+(.)/g, function(match, chr) {
            return chr.toUpperCase();
        });
    }

    _getStatementForEffect(effect, methods) {
        /**
         * This function loops over an array of objects containing a resourceArn and
         * conditions statement and generates the array of statements
         * for the policy.
         */
        let statements = [];

        if (methods.length > 0) {
            let statement = this._getEmptyStatement(effect);

            methods.forEach(curMethod => {

                if (curMethod['conditions'] == '' || curMethod['conditions'].length == 0) {
                    statement.Resource = curMethod['resourceArn'];
                } else {
                    let conditionalStatement = this._getEmptyStatement(effect);
                    conditionalStatement.Resource = curMethod['resourceArn'];
                    conditionalStatement.Condition = curMethod['conditions'];
                    statements.push(conditionalStatement);
                }
                if (statement['Resource']) {
                    statements.push(statement);
                }
            });
        }
        return statements;
    }

    allowAllMethods() {
        /**
         * Adds a ' * ' allow to the policy to authorize access to all methods of an API
         */
        this._addMethod('Allow', this.httpVerbs.ALL, '*', []);
    }
    denyAllMethods() {
        /**
         * Adds a ' * ' allow to the policy to deny access to all methods of an API
         */
        this._addMethod('Deny', this.httpVerbs.ALL, '*', []);
    }
    allowMethod(verb, resource) {
        /**
         * Adds an API Gateway method (Http verb + Resource path) to the list of allowed
         * methods for the policy
         */
        this._addMethod('Allow', verb, resource, []);
    }
    denyMethod(verb, resource) {
        /**
         * Adds an API Gateway method (Http verb + Resource path) to the list of denied
         * methods for the policy
         */
        this._addMethod('Deny', verb, resource, []);

    }
    allowMethodWithConditions(verb, resource, conditions) {

        /**
         * Adds an API Gateway method (Http verb + Resource path) to the list of allowed
         * methods and includes a condition
         * for the policy statement.More on AWS policy
         * conditions here: http: //docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements.html#Condition'''
         */
        this._addMethod('Allow', verb, resource, conditions);

    }
    denyMethodWithConditions(verb, resource, conditions) {
        /**
         * Adds an API Gateway method (Http verb + Resource path) to the list of denied
         * methods and includes a condition
         * for the policy statement.More on AWS policy
         * conditions here: http: //docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements.html#Condition'''
         */
        this._addMethod('Deny', verb, resource, conditions);

    }

    build() {
        /**
         * Generates the policy document based on the internal lists of allowed and denied
         *         conditions. This will generate a policy with two main statements for the effect:
         *         one statement for Allow and one statement for Deny.
         *         Methods that includes conditions will have their own statement in the policy.
         */

        if ((!Array.isArray(this.allowMethods) || this.allowMethods.length == 0) &&
            (!Array.isArray(this.denyMethods) || this.denyMethods.length == 0)) {
            throw ('No statements defined for the policy');
        }
        let policy = {
            'principalId': this.networkId,
            'policyDocument': {
                'Version': this.version,
                'Statement': []
            },
            'context': {
                'networkId': networkId
            },
            'usageIdentifierKey': userIdentifierKey
        };

        if (this.allowMethods.length > 0) {
            policy['policyDocument']['Statement'].push(this._getStatementForEffect('Allow', this.allowMethods)[0]);
        }
        if (this.denyMethods.length > 0) {
            policy['policyDocument']['Statement'].push(this._getStatementForEffect('Deny', this.denyMethods)[0]);
        }
        return policy;
    }
}
const auth_token_decode = async function(auth_token) {
    /**
     * Checks whether JWT Token is valid or not.
     * If valid returns True else False
     */
    let secret = await _getPrivateKeyValue();

    try {
        var decoded = jwt.decode(auth_token,
            secret['partner.api.jwt.token.secret'],
            "HS256");
        networkId = decoded.sub;
        //TODO: get identifier key
        userIdentifierKey = 'xZkeL7RMx06yeITqSw6dS9EuamnGtQOJ4Vi2W3Dq';

        return true;
    } catch (e) {
        console.log(e);
        return false;
    }
};

const create_policy = function(method_arn, principal_id) {
    let tmp = method_arn.split(':');
    let region = tmp[3];
    let account_id = tmp[4];
    let tmp2 = tmp[5].split('/');
    let api_id = tmp2[0];
    let stage = tmp2[1];

    let policy = new AuthPolicy(principal_id, account_id);
    policy.restApiId = api_id;
    policy.region = region;
    policy.stage = stage;
    policy.methodArn = method_arn;

    return policy;
};


const _getPrivateKeyValue = async function() {

    // Create a Secrets Manager client
    var client = new AWS.SecretsManager({
        region: region
    });
    return new Promise((resolve, reject) => {
        client.getSecretValue({ SecretId: secretName }, function(err, data) {
            if (err) {
                reject(err);
            } else {
                if ('SecretString' in data) {
                    resolve(JSON.parse(data.SecretString));
                } else {
                    let buff = new Buffer(data.SecretBinary, 'base64');
                    resolve(JSON.parse(buff.toString('ascii')));
                }
            }
        });
    });
};