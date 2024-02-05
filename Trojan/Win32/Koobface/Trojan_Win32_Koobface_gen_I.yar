
rule Trojan_Win32_Koobface_gen_I{
	meta:
		description = "Trojan:Win32/Koobface.gen!I,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {e8 79 11 00 00 b9 ff 00 00 00 33 c0 8d bc 24 14 02 00 00 33 db f3 ab 66 ab aa 53 8d 84 24 18 02 00 00 6a 1a } //01 00 
		$a_03_1 = {8d 85 50 ff ff ff 53 50 ff 15 90 01 04 68 90 01 04 8d 85 a0 fe ff ff 68 90 01 04 50 c6 85 90 01 04 68 c6 85 90 01 04 74 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}