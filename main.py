from website import create_app

app = create_app()

if __name__ == "__main__": # to run when only open this file not when import this file
    app.run(debug = True) # start up a web server (with debug = True will automaticaly rerun web server everytime python files get edited)
