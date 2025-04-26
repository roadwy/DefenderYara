
rule Trojan_BAT_Bladabindi_AXMA_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.AXMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {1a 2c 32 00 2b 14 2b 19 2b 1e 1e 2d 06 26 16 2d 04 de 22 2b 1a 19 2c ec 2b f4 28 ?? 00 00 06 2b e5 28 ?? 00 00 2b 2b e0 28 ?? 00 00 2b 2b db 0a 2b e3 26 de cb } //4
		$a_01_1 = {52 65 76 65 72 73 65 } //1 Reverse
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}