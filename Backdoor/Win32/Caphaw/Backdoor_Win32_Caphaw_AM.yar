
rule Backdoor_Win32_Caphaw_AM{
	meta:
		description = "Backdoor:Win32/Caphaw.AM,SIGNATURE_TYPE_PEHSTR_EXT,05 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {2f 68 69 6a 61 63 6b 63 66 67 2f 70 6c 75 67 69 6e 73 2f 70 6c 75 67 69 6e } //2 /hijackcfg/plugins/plugin
		$a_01_1 = {2f 68 69 6a 61 63 6b 63 66 67 2f 75 72 6c 73 5f 73 65 72 76 65 72 2f 75 72 6c 5f 73 65 72 76 65 72 } //2 /hijackcfg/urls_server/url_server
		$a_01_2 = {61 00 63 00 74 00 69 00 6f 00 6e 00 3d 00 73 00 65 00 74 00 53 00 74 00 61 00 74 00 75 00 73 00 26 00 62 00 69 00 64 00 3d 00 25 00 73 00 26 00 73 00 6b 00 79 00 70 00 65 00 5f 00 65 00 78 00 69 00 73 00 74 00 73 00 3d 00 25 00 73 00 26 00 70 00 6f 00 6c 00 69 00 63 00 79 00 3d 00 25 00 73 00 } //1 action=setStatus&bid=%s&skype_exists=%s&policy=%s
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=3
 
}