
rule Trojan_BAT_Tedy_PSTW_MTB{
	meta:
		description = "Trojan:BAT/Tedy.PSTW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {28 2a 00 00 0a 72 3f 02 00 70 6f 2b 00 00 0a 0a 72 61 02 00 70 0b 73 2c 00 00 0a 0c 28 01 00 00 2b 0d 73 2e 00 00 0a 13 04 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}