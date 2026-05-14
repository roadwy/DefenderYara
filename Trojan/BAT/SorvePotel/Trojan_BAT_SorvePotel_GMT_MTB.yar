
rule Trojan_BAT_SorvePotel_GMT_MTB{
	meta:
		description = "Trojan:BAT/SorvePotel.GMT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_01_0 = {fe 0c 1b 00 fe 0c 17 00 46 fe 0c 02 00 61 52 fe 0c 17 00 20 01 00 00 00 58 fe 0e 17 00 fe 0c 1b 00 20 01 00 00 00 58 fe 0e 1b 00 } //10
		$a_01_1 = {43 43 53 59 53 43 41 4c 4c 4d 6b 72 65 66 61 6e 79 } //1 CCSYSCALLMkrefany
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}
rule Trojan_BAT_SorvePotel_GMT_MTB_2{
	meta:
		description = "Trojan:BAT/SorvePotel.GMT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_01_0 = {fe 0c 27 00 fe 0c 18 00 3b 30 00 00 00 fe 0c 08 00 fe 0c 27 00 46 fe 0c 0b 00 61 52 fe 0c 27 00 20 01 00 00 00 58 fe 0e 27 00 fe 0c 08 00 20 01 00 00 00 58 fe 0e 08 00 38 c2 ff ff ff } //10
		$a_01_1 = {54 6f 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 ToBase64String
		$a_01_2 = {48 4d 41 43 53 48 41 32 35 36 } //1 HMACSHA256
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=12
 
}