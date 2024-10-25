using DatabaseContextApp;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using SaleSystemModels;

[ApiController]
[Route("[controller]")]
[Authorize]
public class employeesController : ControllerBase
{
    private readonly AppDbContext _context;

    public employeesController(AppDbContext context)
    {
        _context = context;
    }

    [HttpGet]
    public async Task<ActionResult<IEnumerable<Employee>>> GetEntities()
    {
        var employees = await _context.Employees.ToListAsync();
        if (employees == null || !employees.Any())
            return NotFound("Companies Not Available");
        return Ok(employees);
    }

    [HttpGet("{id}")]
    public async Task<ActionResult<Employee>> GetEntity(int id)
    {
        var employee = await _context.Employees.FindAsync(id);
        if (employee == null)
        {
            return NotFound();
        }
        return Ok(employee);
    }

    [HttpPost]
    public async Task<ActionResult<Employee>> CreateEntity(Employee employee)
    {
        _context.Employees.Add(employee);
        await _context.SaveChangesAsync();
        return CreatedAtAction(nameof(GetEntity), new { id = employee.Id }, employee);
    }

    [HttpPut("{id}")]
    public async Task<IActionResult> UpdateEntity(int id, Employee employee)
    {
        if (id != employee.Id)
        {
            return BadRequest();
        }
        _context.Entry(employee).State = EntityState.Modified;
        await _context.SaveChangesAsync();
        return NoContent();
    }

    [HttpDelete("{id}")]
    public async Task<IActionResult> DeleteEntity(int id)
    {
        var employee = await _context.Employees.FindAsync(id);
        if (employee == null)
        {
            return NotFound();
        }
        _context.Employees.Remove(employee);
        await _context.SaveChangesAsync();
        return NoContent();
    }
}