
rule Trojan_BAT_Tedy_EPL_MTB{
	meta:
		description = "Trojan:BAT/Tedy.EPL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 02 07 6f a6 00 00 0a 03 07 6f a6 00 00 0a 61 60 0a 07 17 58 0b 07 02 6f 3f 00 00 0a 32 e1 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}