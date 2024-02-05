
rule Trojan_Win32_Thetatic_A{
	meta:
		description = "Trojan:Win32/Thetatic.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {eb 04 49 30 24 39 83 f9 00 77 f7 } //02 00 
		$a_01_1 = {eb 15 80 3e 5c 75 09 c6 07 5c 47 c6 07 5c eb 04 } //01 00 
		$a_01_2 = {63 73 74 79 70 65 3d 73 65 72 76 65 72 } //01 00 
		$a_01_3 = {63 6f 6d 6d 61 6e 64 3d 72 65 73 75 6c 74 } //01 00 
		$a_01_4 = {76 61 6c 73 5b 69 5d 5e 6b 65 79 63 6f 64 65 } //00 00 
	condition:
		any of ($a_*)
 
}