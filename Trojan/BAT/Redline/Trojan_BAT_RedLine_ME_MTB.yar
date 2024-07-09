
rule Trojan_BAT_RedLine_ME_MTB{
	meta:
		description = "Trojan:BAT/RedLine.ME!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0d 16 13 04 2b 22 09 11 04 9a 13 05 06 11 05 6f ?? ?? ?? 06 2c 0c 06 6f ?? ?? ?? 06 2c 04 17 0b 2b 0d 11 04 17 58 13 04 11 04 09 8e 69 32 d7 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}
rule Trojan_BAT_RedLine_ME_MTB_2{
	meta:
		description = "Trojan:BAT/RedLine.ME!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {08 02 16 02 8e 69 6f ?? ?? ?? 0a 08 6f ?? ?? ?? 0a de 0a 08 2c 06 08 6f ?? ?? ?? 0a dc 07 6f ?? ?? ?? 0a 0d de 14 } //5
		$a_03_1 = {0b 16 0c 2b 78 06 08 9a 16 9a 72 ?? ?? ?? 70 28 ?? ?? ?? 0a 2d 11 06 08 9a 16 9a } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}
rule Trojan_BAT_RedLine_ME_MTB_3{
	meta:
		description = "Trojan:BAT/RedLine.ME!MTB,SIGNATURE_TYPE_PEHSTR_EXT,11 00 11 00 08 00 00 "
		
	strings :
		$a_01_0 = {57 f5 02 3c 09 0f 00 00 00 f0 00 30 00 06 00 00 01 00 00 00 57 00 00 00 53 00 00 00 8a 00 00 00 e3 00 00 00 1b } //10
		$a_01_1 = {47 65 74 54 65 6d 70 50 61 74 68 } //1 GetTempPath
		$a_01_2 = {67 65 74 5f 45 78 65 63 75 74 61 62 6c 65 50 61 74 68 } //1 get_ExecutablePath
		$a_01_3 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_4 = {47 65 74 42 79 74 65 73 } //1 GetBytes
		$a_01_5 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_6 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //1 TransformFinalBlock
		$a_01_7 = {66 64 73 66 66 66 66 64 66 66 73 64 66 } //1 fdsffffdffsdf
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=17
 
}