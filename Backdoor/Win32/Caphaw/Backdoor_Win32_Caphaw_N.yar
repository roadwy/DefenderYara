
rule Backdoor_Win32_Caphaw_N{
	meta:
		description = "Backdoor:Win32/Caphaw.N,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {53 68 e8 03 00 00 6a 02 53 ff 35 90 01 04 ff 35 90 01 04 68 ff ff 00 00 ff 15 90 01 04 85 c0 74 29 8b 35 90 01 04 eb 14 90 00 } //01 00 
		$a_01_1 = {6d 73 70 72 65 61 64 6d 75 74 65 78 } //01 00  mspreadmutex
		$a_01_2 = {2f 68 69 6a 61 63 6b 63 66 67 2f 75 72 6c 73 5f 73 65 72 76 65 72 2f 75 72 6c 5f 73 65 72 76 65 72 } //00 00  /hijackcfg/urls_server/url_server
	condition:
		any of ($a_*)
 
}