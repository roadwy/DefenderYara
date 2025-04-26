
rule Adware_MacOS_Adload_R_MTB{
	meta:
		description = "Adware:MacOS/Adload.R!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 18 f7 c3 80 80 80 80 0f 85 ?? ?? ?? ?? 88 1a 8a 48 01 88 4a 01 8a 48 02 88 4a 02 8a 48 03 88 4a 03 48 83 c2 04 48 83 c0 04 49 83 c4 fc 49 83 fc 03 } //1
		$a_03_1 = {bb ff 07 00 00 b8 01 00 00 00 41 8a 0c 1c 80 e1 c0 80 f9 80 75 ?? 48 ff c0 48 ff cb 48 83 f8 04 76 ?? bb 00 08 00 00 4c 89 ff 4c 89 e6 48 89 da e8 3f f9 ff ff 49 01 dc 49 29 de } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}