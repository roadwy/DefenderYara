
rule Trojan_BAT_Tedy_PSMK_MTB{
	meta:
		description = "Trojan:BAT/Tedy.PSMK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 73 0f 00 00 0a 0a 06 72 01 00 00 70 6f 90 01 03 0a 00 06 72 1f 00 00 70 6f 90 01 03 0a 00 06 17 6f 90 01 03 0a 00 06 16 6f 13 00 00 0a 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}