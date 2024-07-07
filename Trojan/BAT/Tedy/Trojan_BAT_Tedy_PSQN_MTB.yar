
rule Trojan_BAT_Tedy_PSQN_MTB{
	meta:
		description = "Trojan:BAT/Tedy.PSQN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {72 01 00 00 70 7e 14 00 00 0a 7e 14 00 00 0a 16 1a 7e 14 00 00 0a 14 12 02 12 03 28 02 00 00 06 13 04 72 41 00 00 70 09 7b 06 00 00 04 8c 1a 00 00 01 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}