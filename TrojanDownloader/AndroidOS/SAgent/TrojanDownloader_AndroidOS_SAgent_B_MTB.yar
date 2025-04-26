
rule TrojanDownloader_AndroidOS_SAgent_B_MTB{
	meta:
		description = "TrojanDownloader:AndroidOS/SAgent.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,08 00 08 00 05 00 00 "
		
	strings :
		$a_00_0 = {69 6c 6f 76 65 79 6f 75 } //1 iloveyou
		$a_00_1 = {61 64 5f 63 68 6f 69 63 65 73 5f 63 6f 6e 74 61 69 6e 65 72 } //1 ad_choices_container
		$a_00_2 = {43 75 53 65 72 76 69 63 65 } //1 CuService
		$a_00_3 = {4b 4b 52 65 63 65 69 76 65 72 } //1 KKReceiver
		$a_03_4 = {21 70 6e 10 ?? ?? 08 00 0a 01 12 02 12 03 12 04 35 03 14 00 34 14 03 00 12 04 48 05 07 03 6e 20 ?? ?? 48 00 0a 06 b7 65 8d 55 4f 05 07 03 d8 03 03 01 d8 04 04 01 28 ed } //5
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_03_4  & 1)*5) >=8
 
}