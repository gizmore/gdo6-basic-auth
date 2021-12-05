<?php
namespace GDO\BasicAuth;

use GDO\Core\GDO_Module;
use GDO\Core\GDT_Secret;
use GDO\Core\Application;

/**
 * BasicAuth module for gdo6.
 * 
 * @author gizmore
 * @since 6.11.1
 */
final class Module_BasicAuth extends GDO_Module
{
    ##############
    ### Module ###
    ##############
    public function onLoadLanguage() { return $this->loadLanguage('lang/basic_auth'); }
    
    ##############
    ### Config ###
    ##############
    public function getConfig()
    {
        return [
            GDT_Secret::make('basic_auth_user')->label('user_name'),
            GDT_Secret::make('basic_auth_pass')->label('password'),
        ];
    }
    public function cfgUsername() { return $this->getConfigVar('basic_auth_user'); }
    public function cfgPassword() { return $this->getConfigVar('basic_auth_pass'); }
    
    ##################
    ### Middleware ###
    ##################
    public function onInit()
    {
    	if (@$_SERVER['REQUEST_METHOD'] === 'OPTIONS')
    	{
    		return;
    	}
    	if (Application::instance()->isWebServer())
    	{
	        if (!isset($_SERVER['PHP_AUTH_USER']))
	        {
	            $this->deny();
	        }
	        else
	        {
	        	if ( ($username = $this->cfgUsername()) &&
	        	     ($password = $this->cfgPassword()) )
	        	{
	        		if (strcasecmp($username, $_SERVER['PHP_AUTH_USER']) !== 0)
	        		{
	        			$this->deny();
	        		}
		        	if (strcasecmp($password, $_SERVER['PHP_AUTH_PW']) !== 0)
		        	{
		        		$this->deny();
		        	}
	        	}
	        }
    	}
    }
    
    private function deny()
    {
        hdr('WWW-Authenticate: Basic realm="'.sitename().'"');
        hdr('HTTP/1.1 401 Unauthorized');
        echo t('err_basic_auth');
        exit;
    }
    
}
