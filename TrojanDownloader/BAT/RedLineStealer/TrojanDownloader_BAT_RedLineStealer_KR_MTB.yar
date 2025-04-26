
rule TrojanDownloader_BAT_RedLineStealer_KR_MTB{
	meta:
		description = "TrojanDownloader:BAT/RedLineStealer.KR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {8e 69 5d 91 7e ?? 00 00 04 fe ?? ?? 00 91 61 d2 6f } //2
		$a_01_1 = {47 65 74 44 6f 6d 61 69 6e } //1 GetDomain
		$a_01_2 = {47 65 74 54 79 70 65 73 } //1 GetTypes
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}