
rule TrojanDownloader_BAT_Bladabindi_B_MTB{
	meta:
		description = "TrojanDownloader:BAT/Bladabindi.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {00 00 04 07 08 16 6f ?? 00 00 0a 13 05 12 05 28 ?? 00 00 0a 6f ?? 00 00 0a 00 00 08 17 d6 0c 08 11 04 13 06 11 06 } //1
		$a_01_1 = {53 6c 65 65 70 } //1 Sleep
		$a_01_2 = {54 6f 43 68 61 72 41 72 72 61 79 } //1 ToCharArray
		$a_01_3 = {54 6f 41 72 72 61 79 } //1 ToArray
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}