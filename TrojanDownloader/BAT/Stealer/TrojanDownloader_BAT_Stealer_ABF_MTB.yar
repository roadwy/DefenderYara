
rule TrojanDownloader_BAT_Stealer_ABF_MTB{
	meta:
		description = "TrojanDownloader:BAT/Stealer.ABF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_03_0 = {09 08 6f 07 ?? ?? 0a 00 00 de 0b 09 2c 07 09 6f 08 ?? ?? 0a 00 dc 08 6f 09 ?? ?? 0a 13 04 de 16 90 0a 48 00 72 01 ?? ?? 70 28 04 ?? ?? 06 0a 06 73 03 ?? ?? 0a 0b 00 73 04 ?? ?? 0a 0c 00 07 16 73 05 ?? ?? 0a 73 06 ?? ?? 0a 0d 00 } //1
		$a_01_1 = {47 5a 69 70 53 74 72 65 61 6d } //1 GZipStream
		$a_01_2 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //1 MemoryStream
		$a_01_3 = {47 65 74 44 6f 6d 61 69 6e } //1 GetDomain
		$a_01_4 = {43 6f 70 79 54 6f } //1 CopyTo
		$a_01_5 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //1 InvokeMember
		$a_01_6 = {54 6f 41 72 72 61 79 } //1 ToArray
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}