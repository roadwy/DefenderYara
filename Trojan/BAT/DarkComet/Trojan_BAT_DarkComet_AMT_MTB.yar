
rule Trojan_BAT_DarkComet_AMT_MTB{
	meta:
		description = "Trojan:BAT/DarkComet.AMT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0a 0c 2b 12 08 06 08 06 93 02 7b 08 00 00 04 07 91 04 60 61 d1 9d 06 17 59 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_DarkComet_AMT_MTB_2{
	meta:
		description = "Trojan:BAT/DarkComet.AMT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 09 16 13 08 11 09 6f ?? ?? ?? 0a 13 0a 2b 3d 11 09 11 08 6f ?? ?? ?? 0a 13 05 09 11 05 6f ?? ?? ?? 06 13 06 11 06 03 28 ?? ?? ?? 0a da 13 07 08 7e 0d 00 00 04 11 07 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_DarkComet_AMT_MTB_3{
	meta:
		description = "Trojan:BAT/DarkComet.AMT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {02 03 11 05 16 6f ?? 00 00 06 28 ?? 00 00 0a 0b 02 03 11 05 17 6f ?? 00 00 06 28 ?? 00 00 0a 0d 18 09 d8 6c 04 28 ?? 00 00 0a 59 07 6c 59 28 } //3
		$a_01_1 = {03 11 05 08 20 00 01 00 00 5d b4 9c 03 11 05 17 d6 11 04 20 00 01 00 00 5d b4 9c 11 05 18 d6 } //2
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}