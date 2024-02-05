
rule Trojan_Win32_Sadacal_A{
	meta:
		description = "Trojan:Win32/Sadacal.A,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0b 00 06 00 00 05 00 "
		
	strings :
		$a_03_0 = {50 56 6a 13 ff 75 90 01 01 c7 45 90 01 01 0a 00 00 00 ff 15 90 00 } //05 00 
		$a_03_1 = {c6 45 d4 5c 47 e8 90 01 04 6a 1a 99 59 f7 f9 80 c2 61 88 54 3d d4 47 83 ff 0b 90 00 } //01 00 
		$a_01_2 = {74 61 73 6b 2f 61 63 63 } //01 00 
		$a_01_3 = {74 61 73 6b 2f 66 69 6c 65 73 } //01 00 
		$a_01_4 = {74 61 73 6b 2f 63 6f 64 65 } //03 00 
		$a_01_5 = {70 61 79 6d 65 6e 74 00 75 70 6c 6f 61 64 00 00 70 72 6f 63 65 73 73 00 73 74 61 74 } //00 00 
	condition:
		any of ($a_*)
 
}