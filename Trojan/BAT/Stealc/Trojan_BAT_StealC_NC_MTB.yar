
rule Trojan_BAT_StealC_NC_MTB{
	meta:
		description = "Trojan:BAT/StealC.NC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {1a 13 0b 2b dc 08 6f 23 00 00 0a 1e 5b 8d 0f 00 00 01 13 05 17 13 0b 2b c8 07 1e 11 05 16 1e 28 90 01 01 00 00 0a 19 90 00 } //3
		$a_03_1 = {13 0b 2b b8 73 90 01 01 00 00 0a 13 06 1b 13 0b 2b ac 00 18 13 0b 90 00 } //3
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*3) >=6
 
}