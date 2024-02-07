
rule Backdoor_Win32_Caphaw_AE{
	meta:
		description = "Backdoor:Win32/Caphaw.AE,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {2f 68 69 6a 61 63 6b 63 66 67 2f 75 72 6c 73 5f 73 65 72 76 65 72 2f 75 72 6c 5f 73 65 72 76 65 72 } //01 00  /hijackcfg/urls_server/url_server
		$a_03_1 = {53 68 e8 03 00 00 6a 02 53 ff 35 90 01 04 ff 35 90 01 04 68 ff ff 00 00 ff 15 90 01 04 85 c0 74 29 8b 35 90 01 04 eb 14 90 00 } //01 00 
		$a_01_2 = {61 00 63 00 74 00 69 00 6f 00 6e 00 3d 00 73 00 65 00 74 00 53 00 74 00 61 00 74 00 75 00 73 00 26 00 62 00 69 00 64 00 3d 00 25 00 73 00 26 00 73 00 6b 00 79 00 70 00 65 00 5f 00 65 00 78 00 69 00 73 00 74 00 73 00 3d 00 25 00 73 00 26 00 } //00 00  action=setStatus&bid=%s&skype_exists=%s&
		$a_00_3 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}