using System;
using System.Data.SqlClient;
using System.Security.Cryptography;
using System.Text;
using System.Windows.Forms;

namespace UserRegistrationApp
{
    public partial class Form1 : Form
    {
        string connectionString = "Data Source=YOUR_SERVER;Initial Catalog=YOUR_DB;Integrated Security=True";

        public Form1()
        {
            InitializeComponent();
        }

        private void btnRegister_Click(object sender, EventArgs e)
        {
            string userId = txtUserId.Text.Trim();
            string password = txtPassword.Text;

            if (string.IsNullOrWhiteSpace(userId) || string.IsNullOrWhiteSpace(password))
            {
                MessageBox.Show("Please enter both User ID and Password.");
                return;
            }

            string salt = GenerateSalt();
            string hash = HashPassword(password, salt);

            using SqlConnection conn = new SqlConnection(connectionString);
            conn.Open();
            string query = "INSERT INTO Users (UserId, PasswordHash, Salt) VALUES (@u, @h, @s)";
            using SqlCommand cmd = new SqlCommand(query, conn);
            cmd.Parameters.AddWithValue("@u", userId);
            cmd.Parameters.AddWithValue("@h", hash);
            cmd.Parameters.AddWithValue("@s", salt);

            try
            {
                cmd.ExecuteNonQuery();
                MessageBox.Show("✅ User registered successfully.");
            }
            catch (SqlException ex)
            {
                MessageBox.Show("❌ Error: " + ex.Message);
            }
        }

        private string GenerateSalt()
        {
            byte[] saltBytes = new byte[16];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(saltBytes);
            return Convert.ToBase64String(saltBytes);
        }

        private string HashPassword(string password, string salt)
        {
            var pbkdf2 = new Rfc2898DeriveBytes(password, Convert.FromBase64String(salt), 10000, HashAlgorithmName.SHA256);
            return Convert.ToBase64String(pbkdf2.GetBytes(32)); // 256-bit hash
        }
    }
}