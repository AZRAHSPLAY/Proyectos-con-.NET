namespace bdconnection;

public class MyMiddleware {
    private readonly RequestDelegate _next;

    public MyMiddleware(RequestDelegate next) {
      _next = next;
    }

    public async Task Invoke(HttpContext context) {

      Console.WriteLine("------------- El Veldadero Middleware ------------");
      await _next(context);
    }

}
