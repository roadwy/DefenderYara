
rule Trojan_BAT_Nanocore_AASS_MTB{
	meta:
		description = "Trojan:BAT/Nanocore.AASS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {16 0c 2b 1a 00 07 08 18 5b 02 08 18 6f 90 01 01 00 00 0a 1f 10 28 90 01 01 00 00 0a 9c 00 08 18 58 0c 08 06 fe 04 0d 09 2d de 90 00 } //3
		$a_01_1 = {47 00 6c 00 2e 00 4c 00 39 00 } //1 Gl.L9
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1) >=4
 
}