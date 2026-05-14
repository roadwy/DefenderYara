
rule Trojan_BAT_Razy_BAA_MTB{
	meta:
		description = "Trojan:BAT/Razy.BAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 06 07 02 07 91 7e 01 00 00 04 07 7e 01 00 00 04 8e 69 5d 91 61 d2 9c 00 07 17 58 0b 07 02 8e 69 fe 04 0d 09 2d d9 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}
rule Trojan_BAT_Razy_BAA_MTB_2{
	meta:
		description = "Trojan:BAT/Razy.BAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {06 08 8f 08 00 00 01 25 71 08 00 00 01 20 aa 00 00 00 61 d2 81 08 00 00 01 08 17 58 0c 08 06 8e 69 32 dd } //2
		$a_81_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_81_2 = {47 65 74 54 65 6d 70 46 69 6c 65 4e 61 6d 65 } //1 GetTempFileName
		$a_81_3 = {57 72 69 74 65 41 6c 6c 42 79 74 65 73 } //1 WriteAllBytes
	condition:
		((#a_01_0  & 1)*2+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=5
 
}