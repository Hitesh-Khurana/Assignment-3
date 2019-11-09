    users = db.session.query(queryinfo).all()
    for post in users:
        print (post.myinputquery, post.myoutputquery)
        return render_template('history.html',posts=users)
    return f'<h1>The user is located in: {post.myinputquery, post.myoutputquery}</h1>'