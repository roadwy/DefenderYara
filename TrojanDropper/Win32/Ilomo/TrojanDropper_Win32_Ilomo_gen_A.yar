
rule TrojanDropper_Win32_Ilomo_gen_A{
	meta:
		description = "TrojanDropper:Win32/Ilomo.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {03 1e 40 00 44 1e 40 00 9e 20 40 00 ce 20 40 00 0b 22 40 00 90 09 04 00 22 00 00 00 } //1
		$a_01_1 = {45 78 70 61 6e 64 45 6e 76 69 72 6f 6e 6d 65 6e 74 53 74 72 69 6e 67 73 41 } //1 ExpandEnvironmentStringsA
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}