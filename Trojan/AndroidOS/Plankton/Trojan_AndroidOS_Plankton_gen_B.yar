
rule Trojan_AndroidOS_Plankton_gen_B{
	meta:
		description = "Trojan:AndroidOS/Plankton.gen!B,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {12 49 12 38 12 27 12 16 12 05 22 00 46 00 1a 01 0e 03 1a 02 76 03 1a 03 6d 01 70 53 ?? 00 10 25 69 00 3b 00 22 00 46 00 1a 01 20 02 1a 02 4f 02 1a 03 6b 01 70 53 ?? 00 10 26 69 00 } //1
		$a_03_1 = {22 00 46 00 1a 01 a0 02 1a 02 da 02 1a 03 6c 01 70 53 ?? 00 10 29 69 00 3a 00 22 00 46 00 1a 01 e1 0b 12 52 1a 03 29 0c 1a 04 73 01 70 54 ?? 00 10 32 69 00 41 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}