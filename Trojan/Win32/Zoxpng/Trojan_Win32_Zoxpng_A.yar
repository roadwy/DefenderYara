
rule Trojan_Win32_Zoxpng_A{
	meta:
		description = "Trojan:Win32/Zoxpng.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {68 74 74 70 3a 2f 2f 25 73 2f 25 30 34 64 2d 25 30 32 64 2f 25 30 34 64 25 30 32 64 25 30 32 64 25 30 32 64 25 30 32 64 25 30 32 64 2e 70 6e 67 } //01 00 
		$a_00_1 = {68 74 74 70 3a 2f 2f 25 73 2f 69 6d 67 72 65 73 3f 71 3d } //01 00 
		$a_02_2 = {42 36 34 3a 5b 25 73 5d 90 02 10 53 74 65 70 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}