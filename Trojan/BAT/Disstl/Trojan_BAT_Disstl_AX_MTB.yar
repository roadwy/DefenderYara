
rule Trojan_BAT_Disstl_AX_MTB{
	meta:
		description = "Trojan:BAT/Disstl.AX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 05 00 00 "
		
	strings :
		$a_00_0 = {20 00 40 01 00 8d 12 00 00 01 0a 2b 09 03 06 16 07 6f 13 00 00 0a 02 06 16 06 8e 69 6f 14 00 00 0a 25 0b 2d e8 } //10
		$a_80_1 = {63 6f 73 74 75 72 61 2e 63 6f 73 74 75 72 61 2e 70 64 62 } //costura.costura.pdb  3
		$a_80_2 = {4e 69 74 72 6f 20 47 65 6e 65 72 61 74 6f 72 5f 50 72 6f 63 65 73 73 65 64 42 79 46 6f 64 79 } //Nitro Generator_ProcessedByFody  3
		$a_80_3 = {69 73 41 74 74 61 63 68 65 64 } //isAttached  3
		$a_80_4 = {72 65 71 75 65 73 74 65 64 41 73 73 65 6d 62 6c 79 4e 61 6d 65 } //requestedAssemblyName  3
	condition:
		((#a_00_0  & 1)*10+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3) >=22
 
}