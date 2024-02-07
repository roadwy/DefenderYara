
rule Backdoor_Win32_Chargit{
	meta:
		description = "Backdoor:Win32/Chargit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 70 72 6f 67 72 61 6d 5c 70 6c 75 67 69 6e 73 5c 6e 70 63 68 61 72 67 69 74 70 6c 75 67 2e 64 6c 6c } //01 00  \program\plugins\npchargitplug.dll
		$a_01_1 = {61 63 74 69 76 65 78 63 61 63 68 65 } //01 00  activexcache
		$a_01_2 = {68 74 74 70 3a 2f 2f 25 73 2f 6e 70 68 2d 75 70 64 61 74 65 2e 63 67 69 3f 25 73 } //01 00  http://%s/nph-update.cgi?%s
		$a_01_3 = {63 68 61 72 67 69 74 70 6c 75 67 5f 77 69 6e 69 6e 65 74 } //00 00  chargitplug_wininet
	condition:
		any of ($a_*)
 
}