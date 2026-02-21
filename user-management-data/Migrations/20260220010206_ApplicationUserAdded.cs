using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

#pragma warning disable CA1814 // Prefer jagged arrays over multidimensional

namespace user_management_data.Migrations
{
    /// <inheritdoc />
    public partial class ApplicationUserAdded : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            //migrationBuilder.DeleteData(
            //    table: "AspNetRoles",
            //    keyColumn: "Id",
            //    keyValue: "995515ea-cb09-48a4-af45-e9d5dbc14f35");

            //migrationBuilder.DeleteData(
            //    table: "AspNetRoles",
            //    keyColumn: "Id",
            //    keyValue: "a569a953-c7dd-4543-9fb4-89ccf675a2a0");

            //migrationBuilder.DeleteData(
            //    table: "AspNetRoles",
            //    keyColumn: "Id",
            //    keyValue: "e617b4bb-54ec-4698-bffc-4e2ce8410c94");

            migrationBuilder.AddColumn<string>(
                name: "RefreshToken",
                table: "AspNetUsers",
                type: "nvarchar(max)",
                nullable: true);

            migrationBuilder.AddColumn<DateTime>(
                name: "RefreshTokenExpiry",
                table: "AspNetUsers",
                type: "datetime2",
                nullable: false,
                defaultValue: new DateTime(1, 1, 1, 0, 0, 0, 0, DateTimeKind.Unspecified));

            //migrationBuilder.InsertData(
            //    table: "AspNetRoles",
            //    columns: new[] { "Id", "ConcurrencyStamp", "Name", "NormalizedName" },
            //    values: new object[,]
            //    {
            //        { "542ed71b-43ab-4460-84c7-79da960f16bb", "3", "HR", "HR" },
            //        { "5e3f38e1-94e5-408b-9136-19285016fdfe", "2", "User", "User" },
            //        { "e1507f3d-b64b-4005-b66e-5f47a9c6d6a8", "1", "Admin", "Admin" }
            //    });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "542ed71b-43ab-4460-84c7-79da960f16bb");

            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "5e3f38e1-94e5-408b-9136-19285016fdfe");

            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "e1507f3d-b64b-4005-b66e-5f47a9c6d6a8");

            migrationBuilder.DropColumn(
                name: "RefreshToken",
                table: "AspNetUsers");

            migrationBuilder.DropColumn(
                name: "RefreshTokenExpiry",
                table: "AspNetUsers");

            migrationBuilder.InsertData(
                table: "AspNetRoles",
                columns: new[] { "Id", "ConcurrencyStamp", "Name", "NormalizedName" },
                values: new object[,]
                {
                    { "995515ea-cb09-48a4-af45-e9d5dbc14f35", "3", "HR", "HR" },
                    { "a569a953-c7dd-4543-9fb4-89ccf675a2a0", "2", "User", "User" },
                    { "e617b4bb-54ec-4698-bffc-4e2ce8410c94", "1", "Admin", "Admin" }
                });
        }
    }
}
