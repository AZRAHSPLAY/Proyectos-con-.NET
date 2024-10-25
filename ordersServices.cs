using DatabaseContextApp;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using SaleSystemModels;

[ApiController]
[Route("[controller]")]
[Authorize]
public class ordersController : ControllerBase
{
    private readonly AppDbContext _context;

    public ordersController(AppDbContext context)
    {
        _context = context;
    }

    [HttpGet]
    public async Task<ActionResult<IEnumerable<Order>>> GetOrders()
    {
        var orders = await _context.Orders.ToListAsync();
        return Ok(orders);
    }

    [HttpGet("details")]
    public async Task<ActionResult<IEnumerable<OrderDetails>>> GetOrderDetails()
    {
        var orderDetails = await _context.OrderDetails.ToListAsync();
        return Ok(orderDetails);
    }

    [HttpGet("articles")]
    public async Task<ActionResult<IEnumerable<Article>>> GetArticles()
    {
        var articles = await _context.Articles.ToListAsync();
        return Ok(articles);
    }

    [HttpGet("invoices")]
    public async Task<ActionResult<IEnumerable<Invoice>>> GetInvoices()
    {
        var invoices = await _context.Invoices.ToListAsync();
        return Ok(invoices);
    }

    [HttpPost("new/{employeeId}")]
    public async Task<IActionResult> CreateOrder(int employeeId, [FromBody] OrderDetails orderInfo)
    {
        var employee = await _context.Employees.FindAsync(employeeId);
        if (employee == null)
            return BadRequest("Employee not Found");

        var articlesList = new List<Article>();

        foreach (var id in orderInfo.ArticleIds)
        {
            var matchingArticles = await _context
                .Articles.Where(a => orderInfo.ArticleIds.Contains(a.Id))
                .ToListAsync();
            articlesList.AddRange(matchingArticles);
        }

        if (!articlesList.Any())
            return BadRequest("No Articles Found");

        var newOrder = new Order
        {
            Id = _context.Orders.Count() + 1,
            Name = $"Order {_context.Orders.Count() + 1}",
            EmployeeId = employee.Id,
            TotalValue = articlesList.Sum(e => e.Value),
            Status = OrderStatus.Pending,
        };

        var newOrderDetails = new OrderDetails
        {
            Id = _context.OrderDetails.Count() + 1,
            OrderId = newOrder.Id,
            ArticleIds = articlesList.Select(e => e.Id).ToArray(),
        };

        _context.Orders.Add(newOrder);
        _context.OrderDetails.Add(newOrderDetails);
        await _context.SaveChangesAsync();

        return CreatedAtAction(nameof(GetOrders), new { id = newOrder.Id }, newOrder);
    }

    [HttpPut("update/{orderId}")]
    public async Task<IActionResult> UpdateOrder(int orderId, [FromBody] OrderDetails order)
    {
        var existingOrder = await _context.Orders.FindAsync(orderId);

        if (existingOrder == null)
            return BadRequest("Order not Found");

        var existingOrderDetails = await _context.OrderDetails.FirstOrDefaultAsync(e =>
            e.OrderId == orderId
        );

        var articlesList = new List<Article>();

        foreach (var id in order.ArticleIds)
        {
            var matchingArticles = await _context
                .Articles.Where(a => order.ArticleIds.Contains(a.Id))
                .ToListAsync();
            articlesList.AddRange(matchingArticles);
        }

        if (!articlesList.Any())
            return BadRequest("No Articles Found");

        existingOrder.TotalValue = articlesList.Sum(e => e.Value);
        existingOrder.Status = OrderStatus.Pending;

        existingOrderDetails.ArticleIds = articlesList.Select(e => e.Id).ToArray();

        await _context.SaveChangesAsync();

        return NoContent();
    }

    [HttpPut("complete/{orderId}")]
    public async Task<IActionResult> CompleteOrder(int orderId)
    {
        var order = await _context.Orders.FindAsync(orderId);
        if (order == null)
            return BadRequest("Order Not Found");

        if (order.Status == OrderStatus.Completed)
            return Ok("Order Already Completed");

        var details = await _context.OrderDetails.FirstOrDefaultAsync(e => e.OrderId == order.Id);
        if (details == null || !details.ArticleIds.Any())
            return BadRequest("Order has no Articles in it");

        order.Status = OrderStatus.Completed;

        var invoice = new Invoice
        {
            Id = _context.Invoices.Count() + 1,
            OrderId = order.Id,
            DeliveryDate = DateTime.UtcNow.AddDays(7),
        };

        _context.Invoices.Add(invoice);
        await _context.SaveChangesAsync();

        return Ok(invoice);
    }

    [HttpPost("articles/")]
    public async Task<IActionResult> AddArticle([FromBody] Article article)
    {
        _context.Articles.Add(article);
        await _context.SaveChangesAsync();
        return Ok(article);
    }
}