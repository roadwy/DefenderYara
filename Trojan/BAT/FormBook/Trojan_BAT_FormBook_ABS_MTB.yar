
rule Trojan_BAT_FormBook_ABS_MTB{
	meta:
		description = "Trojan:BAT/FormBook.ABS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {08 09 16 20 ?? ?? ?? 00 6f ?? ?? ?? 0a 13 05 11 05 16 fe 02 13 06 11 06 2c 2d 00 11 04 72 ?? ?? ?? 70 18 19 8d ?? ?? ?? 01 25 16 09 a2 25 17 16 8c ?? ?? ?? 01 a2 25 18 11 05 8c ?? ?? ?? 01 a2 28 ?? ?? ?? 0a 26 00 00 11 05 16 fe 02 13 07 11 07 2d ac 11 04 6f ?? ?? ?? 0a 0b 00 de 0d } //5
		$a_01_1 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_01_2 = {47 5a 69 70 53 74 72 65 61 6d } //1 GZipStream
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}
rule Trojan_BAT_FormBook_ABS_MTB_2{
	meta:
		description = "Trojan:BAT/FormBook.ABS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 08 00 00 "
		
	strings :
		$a_01_0 = {57 95 a2 29 09 0f 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 49 00 00 00 15 00 00 00 3c 00 00 00 5c 00 00 00 4c 00 00 00 } //5
		$a_01_1 = {67 65 74 5f 49 73 41 74 74 61 63 68 65 64 } //1 get_IsAttached
		$a_01_2 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_01_3 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //1 TransformFinalBlock
		$a_01_4 = {47 65 74 52 65 73 70 6f 6e 73 65 53 74 72 65 61 6d } //1 GetResponseStream
		$a_01_5 = {67 65 74 5f 43 75 72 72 65 6e 74 44 6f 6d 61 69 6e } //1 get_CurrentDomain
		$a_01_6 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_7 = {43 6f 6e 66 75 73 65 72 } //1 Confuser
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=12
 
}