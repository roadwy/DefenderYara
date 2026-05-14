
rule Trojan_Win32_Wraithbot_AWR_MTB{
	meta:
		description = "Trojan:Win32/Wraithbot.AWR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 04 00 00 "
		
	strings :
		$a_01_0 = {6b c1 28 6a 00 8b 4c 28 24 ff 74 28 28 8d 04 19 50 8b 44 24 20 03 c1 50 ff 74 24 28 ff d6 8b 4c 24 10 0f b7 47 06 41 89 4c 24 10 } //4
		$a_01_1 = {77 00 72 00 61 00 69 00 74 00 68 00 62 00 6f 00 74 00 2e 00 6e 00 65 00 74 00 } //3 wraithbot.net
		$a_01_2 = {62 6f 74 6b 69 6c 6c 65 72 5f 73 63 61 6e } //1 botkiller_scan
		$a_01_3 = {62 6f 74 6b 69 6c 6c 65 72 5f 63 6c 65 61 6e } //1 botkiller_clean
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*3+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=9
 
}