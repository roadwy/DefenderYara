
rule TrojanDownloader_BAT_Maoloa_A_MTB{
	meta:
		description = "TrojanDownloader:BAT/Maoloa.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 08 00 00 "
		
	strings :
		$a_03_0 = {08 8e 69 5d 91 07 09 91 61 d2 6f 90 09 08 00 16 0d 2b 90 01 01 06 09 08 09 90 00 } //2
		$a_03_1 = {00 00 0a 25 02 6f 90 01 01 00 00 0a 0a 6f 90 01 01 00 00 0a 06 0b de 90 00 } //2
		$a_01_2 = {47 65 74 54 79 70 65 } //1 GetType
		$a_01_3 = {54 6f 41 72 72 61 79 } //1 ToArray
		$a_01_4 = {47 65 74 4d 65 74 68 6f 64 } //1 GetMethod
		$a_01_5 = {43 72 65 61 74 65 44 65 6c 65 67 61 74 65 } //1 CreateDelegate
		$a_01_6 = {44 79 6e 61 6d 69 63 49 6e 76 6f 6b 65 } //1 DynamicInvoke
		$a_01_7 = {54 6f 53 74 72 69 6e 67 } //1 ToString
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=10
 
}