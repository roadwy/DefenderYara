
rule Trojan_BAT_Lumma_MBXT_MTB{
	meta:
		description = "Trojan:BAT/Lumma.MBXT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 03 00 00 "
		
	strings :
		$a_01_0 = {41 00 53 00 66 00 67 00 72 00 67 00 68 00 74 00 72 00 68 00 74 00 72 00 } //4 ASfgrghtrhtr
		$a_01_1 = {41 56 50 00 4b 41 4a 53 44 6b 6a 7a 6e 4b 4c 6a 7a 73 6a 6c 6b 65 6a } //3
		$a_01_2 = {33 38 32 63 66 65 66 61 39 61 64 66 } //1 382cfefa9adf
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*3+(#a_01_2  & 1)*1) >=8
 
}