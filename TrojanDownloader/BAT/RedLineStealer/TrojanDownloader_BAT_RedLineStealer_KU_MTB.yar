
rule TrojanDownloader_BAT_RedLineStealer_KU_MTB{
	meta:
		description = "TrojanDownloader:BAT/RedLineStealer.KU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {08 8e 69 5d 91 07 11 ?? 91 61 d2 6f } //2
		$a_01_1 = {47 65 74 4d 65 74 68 6f 64 73 } //1 GetMethods
		$a_01_2 = {47 65 74 54 79 70 65 73 } //1 GetTypes
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}