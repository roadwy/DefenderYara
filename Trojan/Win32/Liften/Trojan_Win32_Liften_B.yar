
rule Trojan_Win32_Liften_B{
	meta:
		description = "Trojan:Win32/Liften.B,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {2d 63 6f 6e 73 6f 6c 65 00 } //01 00 
		$a_00_1 = {4e 44 49 53 52 44 00 } //03 00 
		$a_03_2 = {8b 00 ff d0 8b 03 50 8b 44 24 90 01 01 8b 84 b8 04 20 00 00 50 8b 44 24 90 01 01 50 a1 90 01 04 8b 00 ff d0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}