
rule Trojan_BAT_NanoBot_DA_MTB{
	meta:
		description = "Trojan:BAT/NanoBot.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {70 02 7b 05 00 00 04 02 7b 04 00 00 04 8c 18 00 00 01 28 90 01 03 0a 90 01 02 04 26 06 2b 03 0a 2b fa 2a 90 00 } //1
		$a_03_1 = {2d 03 26 2b 1b 0a 2b fb 06 90 01 01 2d 0a 26 06 17 58 90 01 02 0a 26 2b 0a 28 90 01 03 0a 2b f0 0a 2b 00 06 1b fe 04 0b 07 2d e0 2a 90 00 } //1
		$a_81_2 = {7b 30 7d 20 77 69 74 68 20 73 70 65 65 64 7b 31 7d 20 6b 6d 2f 68 } //1 {0} with speed{1} km/h
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}