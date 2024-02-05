
rule Trojan_Win32_Temvekil_A{
	meta:
		description = "Trojan:Win32/Temvekil.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {8a d0 80 e2 03 80 c2 4d 30 14 08 40 3b c6 7c } //01 00 
		$a_01_1 = {ba fe ff 00 00 66 01 94 4c 90 00 00 00 41 3b c8 7c } //01 00 
		$a_01_2 = {74 61 73 6b 6b 69 6c 6c 20 2f 66 20 2f 69 6d 20 74 65 61 6d 76 69 65 77 65 72 2e 65 } //00 00 
	condition:
		any of ($a_*)
 
}