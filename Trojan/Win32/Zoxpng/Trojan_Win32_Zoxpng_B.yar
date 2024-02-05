
rule Trojan_Win32_Zoxpng_B{
	meta:
		description = "Trojan:Win32/Zoxpng.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {5f 69 69 73 6b 69 6c 6c 90 02 10 43 6c 65 61 72 46 69 6c 65 90 00 } //01 00 
		$a_00_1 = {53 74 61 72 74 53 68 65 6c 6c 00 00 50 61 73 73 77 6f 72 64 3a } //02 00 
		$a_00_2 = {43 6c 65 61 72 46 69 6c 65 00 53 74 61 72 74 53 68 65 6c 6c 00 67 5f 69 69 73 65 78 69 74 00 67 5f 69 69 73 6b 69 6c 6c } //00 00 
	condition:
		any of ($a_*)
 
}