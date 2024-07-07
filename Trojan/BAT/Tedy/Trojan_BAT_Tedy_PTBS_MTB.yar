
rule Trojan_BAT_Tedy_PTBS_MTB{
	meta:
		description = "Trojan:BAT/Tedy.PTBS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {7d 06 00 00 04 02 28 90 01 01 00 00 0a 00 00 02 28 90 01 01 00 00 06 00 16 28 90 01 01 00 00 0a 00 72 07 00 00 70 72 15 00 00 70 28 90 01 01 00 00 0a 28 90 01 01 00 00 0a 00 2a 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}