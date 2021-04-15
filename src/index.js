'use strict';
//const jwt = require('./validator');
//const token = require('./token')
//const uuid = require('uuid');

var AWS = require("aws-sdk");

AWS.config.setPromisesDependency(require('bluebird'));
const dynamoDb = new AWS.DynamoDB.DocumentClient();

exports.handler = function(event, context, callback) {
    const params = {
        TableName: 'partner_api',
        Key: {
            uuid: event.body.id,
        }
    };

    let result = dynamoDb.get(params, function(err, data) {
        if (err) {
            console.error("Unable to read item. Error JSON:", JSON.stringify(err, null, 2));
        } else {
            console.log("GetItem succeeded:", JSON.stringify(data, null, 2));
        }
    });
    console.log(result);
    return result;

    /*
        try {


            if (res) {
                return {
                    "statusCode": 200,
                    "body": ujson.dumps({
                        "message": "Welcome !",
                        "data": {
                            "token": result.load(body)['token']
                        }
                    })
                }
            } else {
                return {
                    "statusCode": 400,
                    "body": ujson.dumps({
                        "message": "Error !",
                        "data": result.validate(body)
                    })
                }
            }
        } catch (e) {
            except ValidationError as err:
                return {
                    "statusCode": 400,
                    "body": ujson.dumps({
                        "message": err.messages
                    })
                }
            except KeyError as error:
                return {
                    "statusCode": 400,
                    "body": ujson.dumps({
                        "message": "Something went wrong. Unable to parse data ! " + str(error)
                    })
                }

        }*/
}
const token_refresh = function(event, context) {
    /*try {
        body = ujson.loads(event['body'])
        result = validator.RefreshTokenSchema()
        res = not bool(result.validate(body))

        if res:
            return {
                "statusCode": 200,
                "body": ujson.dumps({
                    "message": None,
                    "data": result.load(body)
                })
            }
        else :
            return {
                "statusCode": 400,
                "body": ujson.dumps({
                    "message": "Error !",
                    "data": result.validate(body)
                })
            }
    } catch (e) {
        except ValidationError as err:
            return {
                "statusCode": 400,
                "body": ujson.dumps({
                    "message": err.messages
                })
            }

        except KeyError:
            return {
                "statusCode": 400,
                "body": ujson.dumps({ "message": "Something went wrong. Unable to parse data !" })
            }
    }*/
}