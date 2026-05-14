
rule Trojan_BAT_QuasarRAT_BAB_MTB{
	meta:
		description = "Trojan:BAT/QuasarRAT.BAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_03_0 = {0a 06 0b 07 ?? ?? 00 00 0a ?? ?? 00 00 0a 0c ?? ?? 00 00 0a 08 ?? ?? 00 00 0a 0d 09 ?? ?? 00 00 0a 14 14 ?? ?? 00 00 0a 26 2a } //2
		$a_01_1 = {53 74 72 52 65 76 65 72 73 65 } //1 StrReverse
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_3 = {49 6e 76 6f 6b 65 } //1 Invoke
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}
rule Trojan_BAT_QuasarRAT_BAB_MTB_2{
	meta:
		description = "Trojan:BAT/QuasarRAT.BAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {00 06 11 06 06 11 06 91 66 d2 9c 06 11 06 06 11 06 91 19 63 06 11 06 91 1b 62 60 d2 9c 06 11 06 06 11 06 91 11 05 11 06 11 05 8e 69 5d 91 61 d2 9c 00 11 06 17 58 13 06 11 06 06 8e 69 fe 04 13 08 11 08 2d bb } //2
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_2 = {49 6e 76 6f 6b 65 } //1 Invoke
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}
rule Trojan_BAT_QuasarRAT_BAB_MTB_3{
	meta:
		description = "Trojan:BAT/QuasarRAT.BAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {0d 00 09 07 ?? ?? 00 00 0a 17 73 ?? 00 00 0a 13 04 00 11 04 06 16 06 8e 69 ?? ?? 00 00 0a 00 00 de 14 11 04 14 fe 01 13 06 11 06 2d 08 11 04 ?? ?? 00 00 0a 00 dc 00 09 ?? ?? 00 00 0a 13 05 de 30 09 14 fe 01 13 06 11 06 2d 07 09 ?? ?? 00 00 0a 00 dc } //3
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_2 = {49 6e 76 6f 6b 65 } //1 Invoke
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}
rule Trojan_BAT_QuasarRAT_BAB_MTB_4{
	meta:
		description = "Trojan:BAT/QuasarRAT.BAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 11 08 11 0e 11 0f ?? ?? 00 00 0a 13 10 11 0c 11 0d 25 17 58 13 0d 12 10 ?? ?? 00 00 0a 9c 11 0d 11 0b fe 04 16 fe 01 13 1d 11 1d 2d 11 11 0c 11 0d 25 17 58 13 0d 12 10 ?? ?? 00 00 0a 9c 11 0d 11 0b fe 04 16 fe 01 13 1d 11 1d 2d 11 11 0c 11 0d 25 17 58 13 0d 12 10 ?? ?? 00 00 0a 9c 11 0e 17 58 13 0e 11 0e 11 08 ?? ?? 00 00 0a fe 04 13 1d 11 1d 2d 0b 00 16 13 0e 11 0f 17 58 13 0f 00 00 11 0d 11 0b fe 04 13 1d 11 1d 3a 6f ff ff ff } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}