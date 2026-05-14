
rule Trojan_BAT_Zusy_SJ_MTB{
	meta:
		description = "Trojan:BAT/Zusy.SJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {11 09 11 0a 25 17 58 13 0a 07 11 0b 91 9c 11 0b 17 58 13 0b 11 0b 11 04 11 08 58 32 e3 11 08 8d 06 00 00 01 13 0c 06 73 24 00 00 0a 13 0d 11 0d 11 0c 6f 25 00 00 0a 16 13 0e 2b 21 } //1
		$a_81_1 = {24 37 37 34 62 39 32 35 33 2d 61 30 62 33 2d 34 34 64 66 2d 39 34 31 62 2d 34 65 38 63 32 33 38 65 33 37 38 37 } //1 $774b9253-a0b3-44df-941b-4e8c238e3787
	condition:
		((#a_00_0  & 1)*1+(#a_81_1  & 1)*1) >=2
 
}
rule Trojan_BAT_Zusy_SJ_MTB_2{
	meta:
		description = "Trojan:BAT/Zusy.SJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {00 28 4c 00 00 0a 0a 00 06 03 28 4d 00 00 0a 6f 4e 00 00 0a 00 06 04 28 4d 00 00 0a 6f 4f 00 00 0a 00 06 17 6f 50 00 00 0a 00 06 18 6f 51 00 00 0a 00 [0-ff] 07 2c 07 07 6f 10 00 00 0a 00 dc 06 2c 07 06 6f 10 00 00 0a 00 dc 08 2a } //1
		$a_81_1 = {24 30 66 38 37 64 65 38 32 2d 30 32 36 36 2d 34 38 63 33 2d 61 65 64 38 2d 31 65 62 35 36 32 38 38 39 30 35 33 } //1 $0f87de82-0266-48c3-aed8-1eb562889053
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1) >=2
 
}