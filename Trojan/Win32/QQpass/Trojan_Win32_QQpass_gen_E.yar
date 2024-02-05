
rule Trojan_Win32_QQpass_gen_E{
	meta:
		description = "Trojan:Win32/QQpass.gen!E,SIGNATURE_TYPE_PEHSTR,04 00 04 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {74 61 73 6b 6b 69 6c 6c 20 2f 66 20 2f 69 6d 20 51 51 } //01 00 
		$a_01_1 = {5c 42 69 6e 5c 71 71 64 61 74 2e 65 78 65 } //02 00 
		$a_01_2 = {26 71 71 70 61 73 73 77 6f 72 64 3d } //01 00 
		$a_01_3 = {2f 53 54 41 52 54 20 51 51 55 49 4e } //02 00 
		$a_01_4 = {eb 12 83 e8 05 f7 d8 1b c0 83 e0 02 83 c0 04 } //01 00 
		$a_01_5 = {4c 6f 67 69 6e 55 69 6e 4c 69 73 74 2e 64 61 74 } //00 00 
	condition:
		any of ($a_*)
 
}