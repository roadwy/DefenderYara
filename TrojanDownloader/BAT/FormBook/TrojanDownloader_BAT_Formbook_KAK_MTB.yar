
rule TrojanDownloader_BAT_Formbook_KAK_MTB{
	meta:
		description = "TrojanDownloader:BAT/Formbook.KAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_03_0 = {8e 69 5d 91 06 [0-02] 91 61 d2 9c 2b 03 0c 2b ?? [0-02] 17 58 [0-02] 2b 03 0b 2b ?? [0-02] 06 8e 69 32 } //1
		$a_03_1 = {00 00 0a 25 02 73 ?? 00 00 0a 6f ?? 00 00 0a 0a 6f ?? 00 00 0a 06 0b de } //1
		$a_01_2 = {47 65 74 42 79 74 65 73 } //1 GetBytes
		$a_01_3 = {47 65 74 54 79 70 65 } //1 GetType
		$a_01_4 = {47 65 74 4d 65 74 68 6f 64 } //1 GetMethod
		$a_01_5 = {43 72 65 61 74 65 44 65 6c 65 67 61 74 65 } //1 CreateDelegate
		$a_01_6 = {44 79 6e 61 6d 69 63 49 6e 76 6f 6b 65 } //1 DynamicInvoke
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}