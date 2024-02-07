
rule Trojan_Win32_Zenpack_EA_MTB{
	meta:
		description = "Trojan:Win32/Zenpack.EA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {41 7a 74 66 61 63 65 6e 49 66 6f 72 2e 47 } //01 00  AztfacenIfor.G
		$a_01_1 = {46 4c 69 76 69 6e 67 64 72 79 70 74 64 61 79 73 66 6f 72 74 68 42 71 } //01 00  FLivingdryptdaysforthBq
		$a_01_2 = {62 65 6f 70 65 6e 67 69 76 65 52 64 61 79 6e 63 61 6e 2e 74 } //01 00  beopengiveRdayncan.t
		$a_01_3 = {47 44 69 76 69 64 65 2e 6f 70 65 6e 71 66 6c 79 4e 64 51 } //01 00  GDivide.openqflyNdQ
		$a_01_4 = {43 2a 2b 2e 70 64 62 } //00 00  C*+.pdb
	condition:
		any of ($a_*)
 
}