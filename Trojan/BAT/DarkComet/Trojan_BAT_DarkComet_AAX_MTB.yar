
rule Trojan_BAT_DarkComet_AAX_MTB{
	meta:
		description = "Trojan:BAT/DarkComet.AAX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_03_0 = {06 14 1a 8d ?? ?? ?? 01 13 04 11 04 16 03 a2 11 04 17 04 a2 11 04 18 05 a2 11 04 19 0e 04 a2 11 04 } //2
		$a_01_1 = {43 00 6f 00 6d 00 69 00 74 00 65 00 } //1 Comite
		$a_01_2 = {47 65 74 45 78 65 63 75 74 69 6e 67 41 73 73 65 6d 62 6c 79 } //1 GetExecutingAssembly
		$a_01_3 = {6f 00 74 00 6f 00 52 00 2e 00 65 00 74 00 69 00 6d 00 6f 00 43 00 } //1 otoR.etimoC
		$a_01_4 = {53 74 72 52 65 76 65 72 73 65 } //1 StrReverse
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=6
 
}