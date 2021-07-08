<?php
namespace GDO\BasicAuth;

use GDO\Core\GDO_Module;
use GDO\Core\GDT_Secret;

/**
 * BasicAuth module for gdo6.
 * 
 * @author gizmore
 * @since 6.10.4
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
            GDT_Secret::make('basic_auth_user')->initial('gdo6'),
            GDT_Secret::make('basic_auth_pass')->initial('gdo6'),
        ];
    }
    public function cfgUsername() { return $this->getConfigVar('basic_auth_user'); }
    public function cfgPassword() { return $this->getConfigVar('basic_auth_pass'); }
    
    ##################
    ### Middleware ###
    ##################
    public function onInit()
    {
        if (!isset($_SERVER['PHP_AUTH_USER']))
        {
            $this->deny();
        }
        else
        {
            if (strcasecmp($this->cfgUsername(), $_SERVER['PHP_AUTH_USER']) !== 0)
            {
                $this->deny();
            }
            if ($this->cfgPassword() !== $_SERVER['PHP_AUTH_PW'])
            {
                $this->deny();
            }
        }
    }
    
    private function deny()
    {
        hdr('WWW-Authenticate: Basic realm="'.sitename().'"');
        hdr('HTTP/1.0 401 Unauthorized');
        echo t('err_basic_auth');
        exit;
    }
    
}
