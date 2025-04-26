
rule Trojan_BAT_Rhadamanthys_ARH_MTB{
	meta:
		description = "Trojan:BAT/Rhadamanthys.ARH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 1b 2d 03 26 2b 66 0a 2b fb 00 72 01 00 00 70 28 ?? ?? ?? 06 73 02 00 00 0a 16 2c 03 26 2b 03 0b 2b 00 73 03 00 00 0a 1b 2d 03 26 2b 03 0c 2b 00 07 16 73 04 00 00 0a 73 05 00 00 0a 0d 09 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_Rhadamanthys_ARH_MTB_2{
	meta:
		description = "Trojan:BAT/Rhadamanthys.ARH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 05 11 06 6f ?? 00 00 0a 0d 00 07 16 fe 01 13 07 11 07 ?? ?? ?? ?? ?? ?? 16 0b 06 13 08 11 08 1f 20 2e 14 11 08 1f 2e 2e 77 } //1
		$a_03_1 = {08 09 1f 41 59 1f 5b 58 d2 28 ?? 00 00 06 00 00 2b 38 09 1f 61 32 07 09 1f 7a fe 02 2b 01 17 00 13 07 11 07 2d 18 00 7e ?? 00 00 04 08 09 1f 61 59 1f 75 58 d2 } //2
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*2) >=3
 
}
rule Trojan_BAT_Rhadamanthys_ARH_MTB_3{
	meta:
		description = "Trojan:BAT/Rhadamanthys.ARH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 "
		
	strings :
		$a_03_0 = {02 11 10 1f 0c 58 28 ?? 00 00 06 13 13 02 11 10 1f 10 58 28 ?? 00 00 06 13 14 02 11 10 1f 14 58 28 ?? 00 00 06 13 15 11 14 16 31 3e 11 14 8d 14 00 00 01 13 16 02 11 15 11 16 16 11 16 8e 69 28 ?? 00 00 0a 7e 07 00 00 04 12 06 7b 0b 00 00 04 11 0f 11 13 58 11 16 11 16 8e 69 12 04 } //2
		$a_01_1 = {31 00 34 00 37 00 2e 00 34 00 35 00 2e 00 34 00 34 00 2e 00 34 00 32 00 } //5 147.45.44.42
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*5) >=7
 
}