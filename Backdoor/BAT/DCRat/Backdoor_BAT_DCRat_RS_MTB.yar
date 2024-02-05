
rule Backdoor_BAT_DCRat_RS_MTB{
	meta:
		description = "Backdoor:BAT/DCRat.RS!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {2b 44 2b 45 2b 4a 2b 4b 18 5b 1e 2c 24 8d 1e 00 00 01 2b 42 16 2b 42 2b 1e 2b 41 2b 42 18 5b 2b 41 08 18 6f 22 00 00 0a 1f 10 28 23 00 00 0a 9c 08 18 58 16 2d fb 0c 08 18 2c cd 06 16 2d f3 32 d8 19 2c d5 07 2a 02 2b b9 6f 24 00 00 0a 2b b4 0a 2b b3 06 2b b2 0b 2b bb 0c 2b bb 07 2b bc 08 2b bb 02 2b bc } //00 00 
	condition:
		any of ($a_*)
 
}