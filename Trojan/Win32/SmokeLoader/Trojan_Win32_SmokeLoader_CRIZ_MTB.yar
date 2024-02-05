
rule Trojan_Win32_SmokeLoader_CRIZ_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.CRIZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {01 04 24 8b 04 24 31 01 } //01 00 
		$a_03_1 = {33 c7 31 44 24 90 01 01 8b 44 24 90 01 01 29 44 24 90 01 01 8b 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}