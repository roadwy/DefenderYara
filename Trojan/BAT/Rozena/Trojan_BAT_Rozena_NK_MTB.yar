
rule Trojan_BAT_Rozena_NK_MTB{
	meta:
		description = "Trojan:BAT/Rozena.NK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {11 04 09 28 15 00 00 0a 7e 14 00 00 0a 16 11 04 7e 14 00 00 0a 16 7e 14 00 00 0a 28 02 00 00 06 15 } //3
		$a_01_1 = {61 76 5f 62 79 70 61 73 73 2e 70 64 62 } //1 av_bypass.pdb
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1) >=4
 
}