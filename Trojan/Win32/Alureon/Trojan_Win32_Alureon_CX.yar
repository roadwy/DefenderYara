
rule Trojan_Win32_Alureon_CX{
	meta:
		description = "Trojan:Win32/Alureon.CX,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {33 c0 8a c8 80 c1 54 30 88 90 01 04 40 3d 90 01 04 72 ed 90 00 } //01 00 
		$a_01_1 = {81 38 58 4b 4e 53 74 } //01 00 
		$a_01_2 = {76 10 8a d1 02 54 24 08 30 14 01 41 3b 4c 24 04 72 f0 } //00 00 
	condition:
		any of ($a_*)
 
}