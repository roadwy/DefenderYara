
rule Trojan_BAT_Tedy_PSQP_MTB{
	meta:
		description = "Trojan:BAT/Tedy.PSQP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 17 8d 01 00 00 1b 25 16 72 41 00 00 70 04 73 2a 00 00 0a a4 01 00 00 1b 73 2b 00 00 0a 0b 06 03 07 6f 2c 00 00 0a 6f 2d 00 00 0a 0c 00 de 0b } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}