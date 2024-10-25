using DatabaseContextApp;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using SaleSystemModels;

[ApiController]
[Route("[controller]")]
[Authorize]
public class companiesController : ControllerBase
{
    private readonly AppDbContext _context;

    public companiesController(AppDbContext context)
    {
        _context = context;
    }

    [HttpGet]
    public async Task<ActionResult<IEnumerable<Company>>> GetCompanies()
    {
        var companies = await _context.Companies.ToListAsync();
        if (companies == null || !companies.Any())
            return NotFound("Companies Not Available");
        return Ok(companies);
    }

    [HttpGet("{id}")]
    public async Task<ActionResult<Company>> GetCompany(int id)
    {
        var company = await _context.Companies.FindAsync(id);
        if (company == null)
            return NotFound("Company Not Available");
        return Ok(company);
    }

    [HttpPost]
    public async Task<ActionResult<Company>> CreateCompany([FromBody] Company company)
    {
        _context.Companies.Add(company);
        await _context.SaveChangesAsync();
        return CreatedAtAction(nameof(GetCompany), new { id = company.Id }, company);
    }

    [HttpPut("{id}")]
    public async Task<IActionResult> UpdateCompany(int id, [FromBody] Company company)
    {
        var existingCompany = await _context.Companies.FindAsync(id);
        if (existingCompany == null)
            return NotFound("Company Not Available");

        existingCompany.Name = company.Name;
        await _context.SaveChangesAsync();
        return Ok(existingCompany);
    }

    [HttpDelete("{id}")]
    public async Task<IActionResult> DeleteCompany(int id)
    {
        var employeeInCompany = await _context
            .Employees.Where(c => c.CompanyId == id)
            .ToListAsync();

        if (employeeInCompany.Any())
            return BadRequest("Employees registered to this Company");

        var existingCompany = await _context.Companies.FindAsync(id);

        if (existingCompany == null)
            return NotFound("Company Not Available");

        _context.Companies.Remove(existingCompany);
        await _context.SaveChangesAsync();
        return NoContent();
    }
}