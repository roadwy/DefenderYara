
rule Trojan_Win32_Redline_AWC_MTB{
	meta:
		description = "Trojan:Win32/Redline.AWC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {51 83 65 fc 90 01 01 8b 45 90 01 01 01 45 90 01 01 8b 45 90 01 01 8b 4d 90 01 01 31 08 90 00 } //01 00 
		$a_03_1 = {c1 e8 05 03 45 90 01 01 c7 05 90 01 08 89 45 90 01 01 8b 45 90 01 01 31 45 90 01 01 8b 45 90 01 01 31 45 90 01 01 8b 45 90 01 01 29 45 90 01 01 68 90 01 04 8d 45 90 01 01 50 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}