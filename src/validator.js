dynamoDb.scan(params, onScan);


export class Validator {
    email = ''
    password = ''

    validate_email_password(data, kwargs) {
        mongo = db.MongoDBConnection()

        database = mongo.connection['myDB']
        collection = database['registrations']
        result = collection.find_one({ "email": data["email"] })
        if (Array.isArray(result) && result.length == 0) {
            throw ('Sorry! You have provided invalid email.');
        } else {
            ph = PasswordHasher()
            try {
                ph.verify(result['password'], data['password'])
                data['token'] = token.create_access_token(result)
            } catch (e) {
                throw ('The password is invalid.')
            }
        }

        return data
    }

}
export class RefreshTokenSchema {
    token = ''

    validate_token(data) {
        let refresh_token = token.refresh_token(data.token)
        if (refresh_token.status) {
            data.token = refresh_token.data
        } else {
            throw refresh_token.message
        }
        return data
    }
}