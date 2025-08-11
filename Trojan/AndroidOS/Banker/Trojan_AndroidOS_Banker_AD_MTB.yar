
rule Trojan_AndroidOS_Banker_AD_MTB{
	meta:
		description = "Trojan:AndroidOS/Banker.AD!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {54 12 c6 0a 6e 10 f0 11 02 00 0a 02 13 00 08 00 32 02 07 00 54 12 c6 0a 6e 20 40 12 02 00 } //1
		$a_01_1 = {54 50 c8 0a 54 00 d2 0a 6e 10 6e 1b 00 00 0c 00 38 00 1f 00 54 51 c8 0a 54 11 d2 0a 6e 10 73 1b 01 00 0c 01 6e 10 26 a8 01 00 0a 02 12 03 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}