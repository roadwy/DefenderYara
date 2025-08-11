
rule Trojan_BAT_DeepSea_MCF_MTB{
	meta:
		description = "Trojan:BAT/DeepSea.MCF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {34 64 30 35 2d 61 32 35 34 2d 34 32 30 35 36 35 62 30 35 66 32 31 } //1 4d05-a254-420565b05f21
		$a_01_1 = {54 00 65 00 74 00 72 00 69 00 73 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 } //1
		$a_01_2 = {57 bf b6 29 09 1e 00 00 00 fa 01 33 00 16 00 00 01 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}