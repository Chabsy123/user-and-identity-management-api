using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

#pragma warning disable CA1814 // Prefer jagged arrays over multidimensional

namespace user_and_identity_management_api.Migrations
{
    /// <inheritdoc />
    public partial class RolesSeeded : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.InsertData(
                table: "AspNetRoles",
                columns: new[] { "Id", "ConcurrencyStamp", "Name", "NormalizedName" },
                values: new object[,]
                {
                    { "657931a1-8a57-400c-8d94-102aaa6b8755", "2", "User", "USER" },
                    { "6a5d170f-3f5d-4d8d-a7d8-0168831821c8", "1", "Admin", "ADMIN" },
                    { "89f68647-d2ee-4f18-b849-966305c5e4a0", "3", "Manager", "MANAGER" }
                });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "657931a1-8a57-400c-8d94-102aaa6b8755");

            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "6a5d170f-3f5d-4d8d-a7d8-0168831821c8");

            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "89f68647-d2ee-4f18-b849-966305c5e4a0");
        }
    }
}
