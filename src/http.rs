
//Parsing function to get back just the 'nut' portion of the URL
fn parse_nut(url: &str) -> String
{
    let mut nut: String = String::from("");
    if url.starts_with("sqrl://")
    {
        let mut temp_url = url.strip_prefix("sqrl://").unwrap();

        temp_url = temp_url.split("?").collect::<Vec<&str>>()[1];

        temp_url = temp_url.split("nut=").collect::<Vec<&str>>()[1];

        temp_url = temp_url.split("&can=").collect::<Vec<&str>>()[0];

        nut.push_str(temp_url);

        return nut;
    } else {
        nut.push_str("Error");
        return nut;
    }
}

fn test_parse_nut()
{
    let url = "sqrl://sqrl.grc.com/cli.sqrl?nut=jLUOj4v1HsZm&can=aHR0cHM6Ly9zcXJsLmdyYy5jb20vZGVtbw";
    assert_eq!("jLUOj4v1HsZm", parse_nut(&url));
}

// Parsing function to get back just the domain portion of the URL
// the exact domain is required to compute the per site private key
pub fn parse_domain(url: &str) -> String
{
    // url param is the SQRL url that looks like: sqrl://example.com/jimbo/?x=6&nut=...
    // need to parse out the "example.com/jimbo"
    if url.starts_with("sqrl://")
    {
        let mut domain: String = String::from("");
        let mut temp_url = url.strip_prefix("sqrl://").unwrap();
        let offset = determine_offset(temp_url.split("?").collect::<Vec<&str>>()[1]);

        temp_url = temp_url.split("?").collect::<Vec<&str>>()[0];

        if temp_url.find("@") != None
        {
            // keep things to the right of the @ symbol
            temp_url = temp_url.split("@").collect::<Vec<&str>>()[1];
        }
        // domain ends at the beginning of the first '/' symbol, eg example.com/
        let end_index = temp_url.find("/").unwrap() as u8;
        // unless theres an extension, which is then given by the offset var
        let mut index = 0;
        for character in temp_url.chars()
        {
            if index == (end_index + offset) || character == '?'
            {
                break;
            } else if index < end_index && (character.is_alphabetic() || character == '.')
            {
                domain.push(character.to_ascii_lowercase());
            } else if index >= end_index && index < (end_index + offset)
            {
                domain.push(character);
            }
            index += 1;
        }
        return domain;
    } else {
        return String::from("Error");
    }
}

//Helper function for the parsers
fn determine_offset(params: &str) -> u8
{
    // given something like
    // x=5&nut=oOB4QOFJux5Z&can=aHR0cHM6Ly9zcXJsLmdyYy5jb20vYWNjb3VudC9jb25uZWN0ZWQtYWNjb3VudHMv

    if params.get(0..1).unwrap() == "x"
    {
        let mut num_str = params.split("&").collect::<Vec<&str>>()[0];
        num_str = num_str.split("=").collect::<Vec<&str>>()[1];

        return num_str.parse::<u8>().unwrap();
    }
    return 0;
}


fn test_parse_domain()
{
    // test cases taken from GRCs SQRL Operating Details pg 7
    // to lowercase
    assert_eq!(String::from("example.com"), parse_domain("sqrl://ExAmPlE.cOm/?nut="));
    // removing specified port num
    assert_eq!(String::from("example.com"), parse_domain("sqrl://example.com:44344/?nut="));
    // removing username prefix
    assert_eq!(String::from("example.com"), parse_domain("sqrl://jonny@example.com/?nut="));
    // removing username:pass prefix
    assert_eq!(String::from("example.com"), parse_domain("sqrl://Jonny:Secret@example.com/?nut="));
    // keeping extended auth domain
    assert_eq!(String::from("example.com/jimbo"), parse_domain("sqrl://example.com/jimbo/?x=6&nut="));
    // stopping at ? and only making domain lowercase, not extended auth
    assert_eq!(String::from("example.com/JIMBO"), parse_domain("sqrl://EXAMPLE.COM/JIMBO?x=16&nut="));

    assert_eq!(String::from("sqrl.grc.com/demo"), parse_domain("sqrl://steve:badpass@SQRL.grc.com:8080/demo/cli.sqrl?x=5&nut=oOB4QOFJux5Z&
can=aHR0cHM6Ly9zcXJsLmdyYy5jb20vYWNjb3VudC9jb25uZWN0ZWQtYWNjb3VudHMv"));
}
