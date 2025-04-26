
rule Trojan_BAT_Tedy_PSPN_MTB{
	meta:
		description = "Trojan:BAT/Tedy.PSPN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 72 01 00 00 70 72 57 00 00 70 6f 16 00 00 0a de 0a 06 2c 06 06 6f 17 00 00 0a dc 72 8d 00 00 70 28 02 00 00 06 26 02 28 18 00 00 0a 2a } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}