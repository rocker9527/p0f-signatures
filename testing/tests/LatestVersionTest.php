<?php
define("TRAVIS_BUILD_NUMBER", getenv('TRAVIS_BUILD_NUMBER'));
define("TRAVIS_JOB_NUMBER", getenv('TRAVIS_JOB_NUMBER'));
define("BROWSER_TYPE", getenv('BROWSER_TYPE'));

class LatestVersionTest extends Sauce\Sausage\WebDriverTestCase
{
    protected $base_url = 'http://127.0.0.1/';
    protected $build = TRAVIS_BUILD_NUMBER;

    public static $browsers = array(
        array(
            'browserName' => BROWSER_TYPE,
            'desiredCapabilities' => array(
                'version' => '',
                'platform' => 'Windows 8',
                'tunnel-identifier' => TRAVIS_JOB_NUMBER
            )
        ),
        array(
            'browserName' => BROWSER_TYPE,
            'desiredCapabilities' => array(
                'version' => '',
                'platform' => 'Windows 7',
                'tunnel-identifier' => TRAVIS_JOB_NUMBER
            )
        ),
        array(
            'browserName' => BROWSER_TYPE,
            'desiredCapabilities' => array(
                'version' => '',
                'platform' => 'Linux',
                'tunnel-identifier' => TRAVIS_JOB_NUMBER
            )
        ),
        array(
            'browserName' => BROWSER_TYPE,
            'desiredCapabilities' => array(
                'version' => '',
                'platform' => 'OS X 10.6',
                'tunnel-identifier' => TRAVIS_JOB_NUMBER
            )
        )
    );


    public function setUpPage()
    {
        //Test the IP of sauce nodes
        //$this->url('http://whatsmyip.org');
        $this->url('http://127.0.0.1/test.php');
    }
	
	function getSigBrowser(){
		if(BROWSER_TYPE == "firefox")
			return 'Firefox';
			
		if(BROWSER_TYPE == "chrome")
			return 'Google Chrome';

        if(BROWSER_TYPE == "opera")
            return 'Opera';

        if(BROWSER_TYPE == "internetexplorer")
            return 'MSIE';

        throw new \Exception("Unknown browser type: ".BROWSER_TYPE);
	}

    public function testPageLoad()
    {
		
        $this->assertContains($this->getSigBrowser(),$this->byCss('*[data-id="http_name"]')->text());

    }

}