
rule TrojanDownloader_BAT_RemcosRAT_C_MTB{
	meta:
		description = "TrojanDownloader:BAT/RemcosRAT.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_03_0 = {0a 0a 00 06 02 6f ?? ?? ?? 0a 0b 00 73 ?? ?? ?? 0a 0c 00 07 08 6f ?? ?? ?? 0a 00 08 6f ?? ?? ?? 0a 0d de } //1
		$a_03_1 = {0a 0c 00 08 07 90 0a 1f 00 02 73 ?? ?? ?? 0a 0a 00 73 ?? ?? ?? 0a 0b 00 06 16 73 ?? ?? ?? 0a 73 } //1
		$a_03_2 = {0a 0b 00 07 6f ?? ?? ?? 0a 72 ?? ?? ?? 70 28 ?? ?? ?? 0a 0c 08 2c ?? 07 0d de } //1
		$a_01_3 = {43 6f 70 79 54 6f } //1 CopyTo
		$a_01_4 = {54 6f 41 72 72 61 79 } //1 ToArray
		$a_01_5 = {47 65 74 4d 65 74 68 6f 64 73 } //1 GetMethods
		$a_01_6 = {54 6f 4c 69 73 74 } //1 ToList
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}