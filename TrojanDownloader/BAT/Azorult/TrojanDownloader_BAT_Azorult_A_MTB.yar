
rule TrojanDownloader_BAT_Azorult_A_MTB{
	meta:
		description = "TrojanDownloader:BAT/Azorult.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {ea 58 66 61 fe ?? ?? 00 61 d1 9d fe ?? ?? 00 20 ?? ?? ?? db 65 20 ?? ?? ?? 24 59 59 25 fe ?? ?? 00 20 ?? ?? ?? 20 20 ?? ?? ?? 17 59 65 20 ?? ?? ?? 08 61 66 20 } //1
		$a_01_1 = {08 11 08 08 11 08 91 11 04 11 08 09 5d 91 61 d2 9c 1f 09 13 0f 38 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}