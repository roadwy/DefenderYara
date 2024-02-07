
rule PWS_Win32_Ldpinch_AH{
	meta:
		description = "PWS:Win32/Ldpinch.AH,SIGNATURE_TYPE_PEHSTR,2c 00 2b 00 0c 00 00 0a 00 "
		
	strings :
		$a_01_0 = {5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 57 69 6e 6c 6f 67 6f 6e 5c 4e 6f 74 69 66 79 } //0a 00  \Windows NT\CurrentVersion\Winlogon\Notify
		$a_01_1 = {53 74 61 72 74 65 72 54 6f 43 73 72 73 73 54 68 72 65 61 64 } //0a 00  StarterToCsrssThread
		$a_01_2 = {63 2e 6d 78 2e 6d 61 69 6c 2e 79 61 68 6f 6f 2e 63 6f 6d } //0a 00  c.mx.mail.yahoo.com
		$a_01_3 = {41 64 64 46 74 70 41 63 63 6f 75 6e 74 73 } //01 00  AddFtpAccounts
		$a_01_4 = {43 4e 65 74 3a 3a 41 64 64 42 6f 74 49 6e 66 6f } //01 00  CNet::AddBotInfo
		$a_01_5 = {43 44 6c 6c 50 72 6f 74 65 63 74 6f 72 3a 3a 50 72 6f 74 65 63 74 44 4c 4c } //01 00  CDllProtector::ProtectDLL
		$a_01_6 = {43 4d 79 53 79 6e 63 53 6f 63 6b 65 74 3a 3a 43 6f 6e 6e 65 63 74 54 6f } //01 00  CMySyncSocket::ConnectTo
		$a_01_7 = {43 46 54 50 50 77 64 3a 3a 7e 43 46 54 50 50 77 64 } //01 00  CFTPPwd::~CFTPPwd
		$a_01_8 = {43 46 54 50 50 77 64 3a 3a 47 65 74 53 6d 61 72 74 46 54 50 } //01 00  CFTPPwd::GetSmartFTP
		$a_01_9 = {43 46 54 50 50 77 64 3a 3a 47 65 74 46 69 6c 65 5a 69 6c 6c 61 } //01 00  CFTPPwd::GetFileZilla
		$a_01_10 = {43 46 54 50 50 77 64 3a 3a 47 65 74 54 6f 74 61 6c 43 6f 6d 6d 61 6e 64 65 72 } //01 00  CFTPPwd::GetTotalCommander
		$a_01_11 = {43 41 75 74 68 6f 6e 74 69 63 61 74 65 48 6f 6f 6b 65 72 3a 3a 48 61 6e 64 6c 65 72 } //00 00  CAuthonticateHooker::Handler
	condition:
		any of ($a_*)
 
}