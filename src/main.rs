// use std::collections::HashMap;

const TEST_URL: &str = "http://sqrl.grc.com/cli.sqrl?nut=jLUOj4v1HsZm&can=aHR0cHM6Ly9zcXJsLmdyYy5jb20vZGVtbw";

fn main() -> Result<(), ureq::Error>  {
    let body: String = ureq::get("http://www.example.com/")
        .set("Example-Header", "header value")
        .call()?
        .into_string()?;
    println!("{:?}", body);
    Ok(())
}
