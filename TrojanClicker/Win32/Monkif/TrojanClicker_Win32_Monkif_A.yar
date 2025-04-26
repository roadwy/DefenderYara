
rule TrojanClicker_Win32_Monkif_A{
	meta:
		description = "TrojanClicker:Win32/Monkif.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {30 14 3e 83 c6 01 3b f1 7c d9 } //1
		$a_01_1 = {83 f8 05 53 56 57 75 11 8b 75 0c e8 } //1
		$a_01_2 = {63 6f 6e 66 69 67 2e 64 6c 6c 00 49 6e 76 6f 6b 65 00 } //1 潣普杩搮汬䤀癮歯e
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}