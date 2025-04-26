
rule Trojan_WinNT_DCPter_gen_A{
	meta:
		description = "Trojan:WinNT/DCPter.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {53 43 53 49 20 6d 69 6e 69 70 6f 72 74 00 } //1 䍓䥓洠湩灩牯t
		$a_01_1 = {72 65 6c 61 79 00 00 00 64 65 6e 69 65 64 00 } //1
		$a_01_2 = {3d 3f 25 73 3f 42 3f 00 48 36 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}