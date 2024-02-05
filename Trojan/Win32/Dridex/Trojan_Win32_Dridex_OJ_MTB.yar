
rule Trojan_Win32_Dridex_OJ_MTB{
	meta:
		description = "Trojan:Win32/Dridex.OJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {89 e6 89 16 89 90 02 03 e8 90 02 04 8b 90 02 03 01 90 01 01 88 90 01 01 8b 90 02 03 89 90 02 06 8b 90 02 03 89 90 02 06 88 90 02 03 66 8b 90 02 06 66 8b 90 02 06 8a 90 02 03 8b 90 02 02 66 29 fe 66 89 90 02 06 8b 90 02 03 c7 90 02 0a 66 8b 90 02 06 66 83 90 02 02 66 89 90 02 06 88 90 02 02 e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}