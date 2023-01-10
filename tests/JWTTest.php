<?php 
use PHPUnit\Framework\TestCase;

/**
*  Corresponding Class to test JWT class
*
*  For each class in your library, there should be a corresponding Unit-Test for it
*  Unit-Tests should be as much as possible independent from other test going on.
*
*  @author yourname
*/
class JWTTest extends TestCase
{
    /**
     * @test
     */
    public function jwt_token_have_correct_structure()
    {
        $jwt = new \Undeadline\JWT();
        $token = $jwt->getAccessToken();

        $this->assertMatchesRegularExpression('/^[\s\S]+\.[\s\S]+\.[\s\S]+$/', $token, 'Token is should have 3 parts');
    }

    /**
     * @test
     */
    public function jwt_tokens_are_equals_with_same_arguments()
    {
        $jwt = new \Undeadline\JWT();
        $jwt->setClaims(['client_id' => 1]);
        $one = $jwt->getAccessToken();
        $jwt->setClaims(['client_id' => 1]);
        $two = $jwt->getAccessToken();

        $this->assertEquals($one, $two, 'Tokens with same arguments are not equals');
    }

    /**
     * @test
     */
    public function jwt_tokens_are_not_equals_with_not_same_arguments()
    {
        $jwt = new \Undeadline\JWT();
        $jwt->setClaims(['client_id' => 1]);
        $one = $jwt->getAccessToken();
        $jwt->setClaims(['client_id' => 2]);
        $two = $jwt->getAccessToken();

        $this->assertNotEquals($one, $two, 'Tokens with not same arguments are equals');
    }

    /**
     * @test
     */
    public function jwt_refresh_token_can_be_getting()
    {
        $jwt = new \Undeadline\JWT();
        $refresh = $jwt->getRefreshToken();

        $this->assertMatchesRegularExpression('/^[\s\S]+$/', $refresh, 'Refresh token can not be empty');
    }

    /**
     * @test
     */
    public function new_jwt_token_with_future_time_is_valid()
    {
        $jwt = new \Undeadline\JWT();
        $jwt->setExpirationTime(time() + 1800);
        $token = $jwt->getAccessToken();

        $this->assertTrue($jwt->validateToken($token));
    }

    /**
     * @test
     */
    public function new_jwt_token_with_past_time_is_not_valid()
    {
        $jwt = new \Undeadline\JWT();
        $jwt->setExpirationTime(time() - 1000);
        $token = $jwt->getAccessToken();

        $this->assertFalse($jwt->validateToken($token));
    }
}
