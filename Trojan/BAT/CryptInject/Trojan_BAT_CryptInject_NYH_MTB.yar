
rule Trojan_BAT_CryptInject_NYH_MTB{
	meta:
		description = "Trojan:BAT/CryptInject.NYH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {57 95 02 28 09 0f 00 00 00 00 00 00 00 00 00 00 01 00 00 00 37 00 00 00 1f 00 00 00 5e 00 00 00 92 00 00 00 31 00 00 00 47 00 00 00 05 00 00 00 09 } //1
		$a_01_1 = {61 52 33 6e 62 66 38 64 51 70 32 66 65 4c 6d 6b 33 31 2e 6c 53 66 67 41 70 61 74 6b 64 78 73 56 63 47 63 72 6b 74 6f 46 64 2e 72 65 73 6f 75 72 63 65 } //1 aR3nbf8dQp2feLmk31.lSfgApatkdxsVcGcrktoFd.resource
		$a_01_2 = {50 6c 61 74 65 73 2e 64 6c 6c } //1 Plates.dll
		$a_01_3 = {47 65 74 50 69 78 65 6c } //1 GetPixel
		$a_01_4 = {54 6f 41 72 67 62 } //1 ToArgb
		$a_01_5 = {42 69 74 43 6f 6e 76 65 72 74 65 72 } //1 BitConverter
		$a_01_6 = {47 65 74 42 79 74 65 73 } //1 GetBytes
		$a_01_7 = {54 6f 49 6e 74 33 32 } //1 ToInt32
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}