
rule TrojanDownloader_BAT_Formbook_KAD_MTB{
	meta:
		description = "TrojanDownloader:BAT/Formbook.KAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 05 00 00 "
		
	strings :
		$a_03_0 = {06 07 93 28 ?? ?? ?? 06 1a 59 0c 20 ?? ?? ?? 00 0d 09 08 2f ?? 08 09 59 0c 2b ?? 16 08 31 ?? 08 09 58 0c 06 07 08 d1 9d 07 17 58 0b 07 06 8e 69 32 } //1
		$a_03_1 = {06 02 07 9a 28 ?? ?? ?? 06 d1 0c 12 ?? 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 0a 07 17 58 0b 07 02 8e 69 32 } //1
		$a_03_2 = {06 07 02 07 28 ?? ?? ?? 06 07 28 ?? ?? ?? 06 61 d1 9d 07 17 58 0b 07 02 6f } //1
		$a_03_3 = {07 06 08 8f ?? ?? ?? 01 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 0b 08 17 59 0c 08 15 30 } //1
		$a_03_4 = {07 08 9a 28 ?? ?? ?? 06 0d 06 08 09 28 ?? ?? ?? 06 9c 08 17 58 0c 08 06 8e 69 32 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1) >=2
 
}