<?php
define("TRAVIS_BUILD_NUMBER", getenv('TRAVIS_BUILD_NUMBER'));

class simpleTest extends Sauce\Sausage\WebDriverTestCase
{
    protected $base_url = 'http://127.0.0.1/';
    protected $build = TRAVIS_BUILD_NUMBER;

    public static $browsers = array(
        array(
            'browserName' => 'firefox',
            'desiredCapabilities' => array(
                'version' => '',
                'platform' => 'Windows 8'
            )
        ),
        array(
            'browserName' => 'firefox',
            'desiredCapabilities' => array(
                'version' => '',
                'platform' => 'Windows 7'
            )
        ),
        array(
            'browserName' => 'firefox',
            'desiredCapabilities' => array(
                'version' => '',
                'platform' => 'Linux'
            )
        ),
        array(
            'browserName' => 'firefox',
            'desiredCapabilities' => array(
                'version' => '',
                'platform' => 'OS X 10.6'
            )
        )
    );


    public function setUpPage()
    {

        $this->url('http://127.0.0.1:4445/test.php');
    }

    public function testPageLoad()
    {

        $this->assertContains('Firefox',$this->byCss('*[data-id="Firefox"]')->attribute('data-test'));

    }

}