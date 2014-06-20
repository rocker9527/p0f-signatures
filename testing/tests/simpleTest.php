<?php
define("TRAVIS_BUILD_NUMBER", getenv('TRAVIS_BUILD_NUMBER'));
define("TRAVIS_JOB_NUMBER", getenv('TRAVIS_JOB_NUMBER'));
define("BROWSER_TYPE", getenv('BROWSER_TYPE'));

class latestVersionTest extends Sauce\Sausage\WebDriverTestCase
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

    public function testPageLoad()
    {

        $this->assertContains('Firefox',$this->byCss('*[data-id="http_name"]')->text());

    }

}