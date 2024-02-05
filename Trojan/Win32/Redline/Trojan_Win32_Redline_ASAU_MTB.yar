
rule Trojan_Win32_Redline_ASAU_MTB{
	meta:
		description = "Trojan:Win32/Redline.ASAU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {33 f6 80 b6 90 02 05 68 90 00 } //01 00 
		$a_01_1 = {75 6a 64 69 73 68 58 2a 26 41 42 68 37 38 33 37 33 33 37 37 } //00 00 
	condition:
		any of ($a_*)
 
}