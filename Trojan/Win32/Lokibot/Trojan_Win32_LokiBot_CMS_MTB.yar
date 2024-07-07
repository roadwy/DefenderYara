
rule Trojan_Win32_LokiBot_CMS_MTB{
	meta:
		description = "Trojan:Win32/LokiBot.CMS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b c1 99 6a 0c 5e f7 fe 8a 82 90 01 04 30 04 0b 41 3b cf 72 90 00 } //5
		$a_81_1 = {47 65 74 54 69 63 6b 43 6f 75 6e 74 } //1 GetTickCount
	condition:
		((#a_03_0  & 1)*5+(#a_81_1  & 1)*1) >=6
 
}