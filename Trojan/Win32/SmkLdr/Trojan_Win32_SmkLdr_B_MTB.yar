
rule Trojan_Win32_SmkLdr_B_MTB{
	meta:
		description = "Trojan:Win32/SmkLdr.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {80 00 98 40 38 18 75 f8 } //01 00 
		$a_03_1 = {66 01 08 8d 40 02 66 39 18 75 f0 90 09 05 00 b9 90 01 02 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}