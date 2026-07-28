import sqlite3
import bcrypt

DATABASE = "users.db"


# =====================================
# Create User Table
# =====================================


def create_users_table():

    conn = sqlite3.connect(DATABASE)

    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users
        (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            username TEXT UNIQUE,

            password TEXT,

            role TEXT
        )
        """)

    conn.commit()

    conn.close()


# =====================================
# Register User
# =====================================


def register_user(username, password, role="user"):

    conn = sqlite3.connect(DATABASE)

    cursor = conn.cursor()

    hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

    try:

        cursor.execute(
            """
            INSERT INTO users
            (
            username,
            password,
            role
            )

            VALUES (?,?,?)
            """,
            (username, hashed_password, role),
        )

        conn.commit()

        return True

    except sqlite3.IntegrityError:

        return False

    finally:

        conn.close()


# =====================================
# Login User
# =====================================


def login_user(username, password):

    conn = sqlite3.connect(DATABASE)

    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT *
        FROM users
        WHERE username=?
        """,
        (username,),
    )

    user = cursor.fetchone()

    conn.close()

    if user:

        stored_password = user[2]

        if bcrypt.checkpw(password.encode(), stored_password):

            return user

    return None


# =====================================
# Get All Users (Admin)
# =====================================


def get_all_users():

    conn = sqlite3.connect(DATABASE)

    cursor = conn.cursor()

    cursor.execute("""
        SELECT id, username, role
        FROM users
        """)

    users = cursor.fetchall()

    conn.close()

    return users


# =====================================
# Delete User (Admin)
# =====================================


def delete_user(user_id):

    conn = sqlite3.connect(DATABASE)

    cursor = conn.cursor()

    cursor.execute(
        """
        DELETE FROM users
        WHERE id=?
        """,
        (user_id,),
    )

    conn.commit()

    conn.close()


# =====================================
# Update User Role (Admin)
# =====================================


def update_role(user_id, role):

    conn = sqlite3.connect(DATABASE)

    cursor = conn.cursor()

    cursor.execute(
        """
        UPDATE users
        SET role=?
        WHERE id=?
        """,
        (role, user_id),
    )

    conn.commit()

    conn.close()


# =====================================
# Update User Role (Admin)
# =====================================


def update_user_role(user_id, role):

    conn = sqlite3.connect(DATABASE)

    cursor = conn.cursor()

    cursor.execute(
        """
        UPDATE users
        SET role=?
        WHERE id=?
        """,
        (role, user_id),
    )

    conn.commit()

    conn.close()
