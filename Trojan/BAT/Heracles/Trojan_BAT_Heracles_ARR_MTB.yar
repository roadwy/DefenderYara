
rule Trojan_BAT_Heracles_ARR_MTB{
	meta:
		description = "Trojan:BAT/Heracles.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_03_0 = {08 17 9c 1f 11 28 ?? ?? ?? ?? 2c 15 1f 43 28 ?? ?? ?? ?? 2d 09 1f 58 } //11
		$a_03_1 = {0a 2c 08 7e ?? ?? ?? ?? 0d de 42 07 28 ?? ?? ?? 06 0c 08 7e } //9
	condition:
		((#a_03_0  & 1)*11+(#a_03_1  & 1)*9) >=20
 
}
rule Trojan_BAT_Heracles_ARR_MTB_2{
	meta:
		description = "Trojan:BAT/Heracles.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {11 04 11 0b 91 1f 18 62 11 04 11 0b 17 58 91 1f 10 62 60 11 04 11 0b 18 58 91 1e 62 60 11 04 11 0b 19 58 91 60 } //15
		$a_01_1 = {11 08 2c 06 11 07 13 06 2b 13 11 07 17 58 13 07 11 07 11 04 8e 69 11 05 8e 69 59 31 b9 } //5
	condition:
		((#a_01_0  & 1)*15+(#a_01_1  & 1)*5) >=20
 
}
rule Trojan_BAT_Heracles_ARR_MTB_3{
	meta:
		description = "Trojan:BAT/Heracles.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 04 00 00 "
		
	strings :
		$a_03_0 = {16 31 0a 12 00 28 ?? ?? ?? ?? 16 30 5c 1f 18 18 73 ?? ?? ?? ?? 13 08 12 08 } //11
		$a_03_1 = {18 5b 0c 12 00 28 ?? ?? ?? ?? 18 5b 0d 08 09 73 ?? ?? ?? ?? 13 04 11 04 } //9
		$a_81_2 = {3c 53 65 74 52 65 6d 6f 74 65 43 6c 69 70 62 6f 61 72 64 3e 62 5f 5f 30 } //6 <SetRemoteClipboard>b__0
		$a_81_3 = {3c 64 65 70 6c 6f 79 6d 65 6e 74 49 64 3e 35 5f 5f 34 } //4 <deploymentId>5__4
	condition:
		((#a_03_0  & 1)*11+(#a_03_1  & 1)*9+(#a_81_2  & 1)*6+(#a_81_3  & 1)*4) >=30
 
}