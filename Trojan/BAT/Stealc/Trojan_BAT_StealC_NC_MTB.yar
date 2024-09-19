
rule Trojan_BAT_StealC_NC_MTB{
	meta:
		description = "Trojan:BAT/StealC.NC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {1a 13 0b 2b dc 08 6f 23 00 00 0a 1e 5b 8d 0f 00 00 01 13 05 17 13 0b 2b c8 07 1e 11 05 16 1e 28 ?? 00 00 0a 19 } //3
		$a_03_1 = {13 0b 2b b8 73 ?? 00 00 0a 13 06 1b 13 0b 2b ac 00 18 13 0b } //3
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*3) >=6
 
}
rule Trojan_BAT_StealC_NC_MTB_2{
	meta:
		description = "Trojan:BAT/StealC.NC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {02 03 02 4b 03 04 5f 03 66 05 5f 60 58 0e 07 0e 04 e0 95 58 7e 70 19 00 04 0e 06 17 59 e0 95 58 0e 05 } //3
		$a_81_1 = {36 39 66 63 38 36 31 38 2d 64 36 61 32 2d 34 39 33 30 2d 39 62 38 37 2d 38 65 66 63 66 64 65 65 35 63 66 32 } //2 69fc8618-d6a2-4930-9b87-8efcfdee5cf2
	condition:
		((#a_01_0  & 1)*3+(#a_81_1  & 1)*2) >=5
 
}