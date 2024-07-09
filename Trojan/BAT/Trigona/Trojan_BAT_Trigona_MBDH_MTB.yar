
rule Trojan_BAT_Trigona_MBDH_MTB{
	meta:
		description = "Trojan:BAT/Trigona.MBDH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {11 09 11 05 16 11 05 8e 69 6f ?? 00 00 0a 13 06 11 08 6f ?? 00 00 0a 11 09 6f ?? 00 00 0a de 24 } //1
		$a_01_1 = {65 35 66 61 38 37 65 63 2d 63 31 63 31 2d 30 38 38 32 2d 39 36 32 31 2d 38 31 32 36 33 61 63 38 65 66 39 31 } //1 e5fa87ec-c1c1-0882-9621-81263ac8ef91
		$a_01_2 = {75 00 75 00 75 00 75 00 75 00 44 00 44 00 44 00 44 00 37 00 37 00 37 00 37 00 37 00 } //1 uuuuuDDDD77777
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}