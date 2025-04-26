
rule Backdoor_Win32_Caphaw_N{
	meta:
		description = "Backdoor:Win32/Caphaw.N,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {53 68 e8 03 00 00 6a 02 53 ff 35 ?? ?? ?? ?? ff 35 ?? ?? ?? ?? 68 ff ff 00 00 ff 15 ?? ?? ?? ?? 85 c0 74 29 8b 35 ?? ?? ?? ?? eb 14 } //1
		$a_01_1 = {6d 73 70 72 65 61 64 6d 75 74 65 78 } //1 mspreadmutex
		$a_01_2 = {2f 68 69 6a 61 63 6b 63 66 67 2f 75 72 6c 73 5f 73 65 72 76 65 72 2f 75 72 6c 5f 73 65 72 76 65 72 } //1 /hijackcfg/urls_server/url_server
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}