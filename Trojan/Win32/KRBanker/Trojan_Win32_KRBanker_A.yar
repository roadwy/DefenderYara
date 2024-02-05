
rule Trojan_Win32_KRBanker_A{
	meta:
		description = "Trojan:Win32/KRBanker.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 61 66 65 62 61 6e 6b 2e 6b 6f 72 65 61 2e 63 6f 2e 6b 72 } //01 00 
		$a_01_1 = {41 59 41 67 65 6e 74 2e 61 79 65 } //01 00 
		$a_01_2 = {42 6c 61 63 6b 4d 6f 6f 6e 20 52 75 6e 54 69 6d 65 20 45 72 72 6f 72 3a } //01 00 
		$a_01_3 = {3f 3d 64 65 6c 65 74 65 64 } //00 00 
		$a_00_4 = {5d 04 00 } //00 47 
	condition:
		any of ($a_*)
 
}