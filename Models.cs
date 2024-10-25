using System.ComponentModel.DataAnnotations.Schema;

namespace SaleSystemModels
{
    public class Company
    {
        public int Id { get; set; }
        public string Name { get; set; }
        // public ICollection<Employee> Employees { get; set; } = new List<Employee>();
    }

    public class Employee
    {
        public int Id { get; set; }
        public string Name { get; set; }

        [ForeignKey("Company")]
        public int CompanyId { get; set; }
    }

    public class Article
    {
        public int Id { get; set; }

        public string Name { get; set; }

        public int Value { get; set; }

        [ForeignKey("Company")]
        public int CompanyId { get; set; }
    }

    public enum OrderStatus
    {
        Completed,
        Pending,
    }

    public class Order
    {
        public int Id { get; set; }

        public string Name { get; set; }

        [ForeignKey("Employee")]
        public int EmployeeId { get; set; }

        public int TotalValue { get; set; }

        public OrderStatus Status { get; set; }
    }

    public class OrderDetails
    {
        public int Id { get; set; }

        [ForeignKey("Article")]
        public int[] ArticleIds { get; set; }

        [ForeignKey("Order")]
        public int OrderId { get; set; }
    }

    public class Invoice
    {
        public int Id { get; set; }

        [ForeignKey("Order")]
        public int OrderId { get; set; }

        public DateTime DeliveryDate { get; set; }
    }
}