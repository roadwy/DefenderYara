
rule Trojan_BAT_RedLineStealer_MHA_MTB{
	meta:
		description = "Trojan:BAT/RedLineStealer.MHA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {43 72 65 61 74 65 45 6e 63 72 79 70 74 6f 72 } //1 CreateEncryptor
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_2 = {63 00 6d 00 64 00 61 00 61 00 61 00 61 00 61 00 61 00 61 00 61 00 61 00 2e 00 65 00 78 00 65 00 } //1 cmdaaaaaaaaa.exe
		$a_01_3 = {6b 00 6d 00 49 00 61 00 67 00 6f 00 6b 00 72 00 53 00 6d 00 } //1 kmIagokrSm
		$a_01_4 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //1 TransformFinalBlock
		$a_01_5 = {47 65 74 42 79 74 65 73 } //1 GetBytes
		$a_01_6 = {54 6f 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 ToBase64String
		$a_01_7 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //1 MemoryStream
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}