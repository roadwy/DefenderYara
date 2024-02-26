
rule Trojan_Win32_Zenpak_MBEY_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.MBEY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 12 8b 00 0f b7 3b 31 d7 89 34 24 89 44 24 04 89 7c 24 08 } //01 00 
		$a_01_1 = {45 68 6f 66 74 61 68 61 6c 6c 6c 71 68 65 54 65 66 6e 72 65 } //00 00  EhoftahalllqheTefnre
	condition:
		any of ($a_*)
 
}