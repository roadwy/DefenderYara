
rule Trojan_WinNT_Simda_gen_B{
	meta:
		description = "Trojan:WinNT/Simda.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {8a 14 01 3a 10 75 ?? 47 40 3b fe 72 ?? eb } //1
		$a_03_1 = {8d 41 9f 66 83 f8 19 77 ?? 81 c1 e0 ff 00 00 eb ?? 0f b7 c9 } //1
		$a_01_2 = {4d 6f 64 75 6c 65 52 30 50 64 6d } //1 ModuleR0Pdm
		$a_01_3 = {41 6d 65 72 69 63 61 20 4f 6e 6c 69 6e 65 20 42 72 6f 77 73 65 72 20 31 2e 31 00 00 3f 4f 39 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}