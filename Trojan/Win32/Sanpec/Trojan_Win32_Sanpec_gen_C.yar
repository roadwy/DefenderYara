
rule Trojan_Win32_Sanpec_gen_C{
	meta:
		description = "Trojan:Win32/Sanpec.gen!C,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {83 ca fc 42 8a 54 15 fc 32 14 06 41 3b cf 88 10 7c e0 } //01 00 
		$a_01_1 = {68 14 e0 22 00 ff 75 08 e8 } //01 00 
		$a_01_2 = {70 73 65 63 5f 6f 6e 63 65 } //00 00 
	condition:
		any of ($a_*)
 
}