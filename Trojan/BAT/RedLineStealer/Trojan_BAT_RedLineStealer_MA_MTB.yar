
rule Trojan_BAT_RedLineStealer_MA_MTB{
	meta:
		description = "Trojan:BAT/RedLineStealer.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_03_0 = {11 07 11 0a 16 11 0a 8e 69 6f ?? ?? ?? 0a 26 38 ?? ?? ?? ff dd ?? ?? ?? ?? 11 07 3a ?? 00 00 00 38 ?? 00 00 00 fe ?? ?? ?? 45 [0-0a] 38 ?? 00 00 00 38 ?? 00 00 00 20 00 00 00 00 7e ?? ?? ?? 04 3a ?? ?? ?? ff 26 20 00 00 00 00 38 ?? ?? ?? ff 11 07 6f ?? ?? ?? 0a 38 00 00 00 00 dc } //1
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 43 68 61 72 41 72 72 61 79 } //1 FromBase64CharArray
		$a_01_2 = {65 74 61 74 53 64 61 65 52 74 65 4e 6d 65 74 73 79 53 } //1 etatSdaeRteNmetsyS
		$a_01_3 = {52 65 70 6c 61 63 65 } //1 Replace
		$a_01_4 = {62 61 73 65 36 34 45 6e 63 6f 64 65 64 44 61 74 61 } //1 base64EncodedData
		$a_01_5 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //1 MemoryStream
		$a_01_6 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}