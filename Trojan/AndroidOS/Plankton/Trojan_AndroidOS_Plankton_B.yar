
rule Trojan_AndroidOS_Plankton_B{
	meta:
		description = "Trojan:AndroidOS/Plankton.B,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {61 6e 64 72 6f 69 64 2e 69 6e 74 65 6e 74 2e 62 72 6f 77 73 65 72 2e 53 45 54 5f 48 4f 4d 45 50 41 47 45 00 } //1
		$a_01_1 = {12 38 12 27 12 16 12 05 22 00 1a 01 1a 01 af 02 1a 02 e8 02 1a 03 bf 0c 70 53 ba 04 10 25 69 00 30 01 22 00 1a 01 1a 01 99 01 1a 02 c5 01 1a 03 c1 0c 70 53 ba 04 10 26 69 00 2e 01 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}