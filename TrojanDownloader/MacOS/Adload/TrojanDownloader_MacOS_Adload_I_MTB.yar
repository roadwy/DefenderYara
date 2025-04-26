
rule TrojanDownloader_MacOS_Adload_I_MTB{
	meta:
		description = "TrojanDownloader:MacOS/Adload.I!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {f6 85 20 ff ff ff 01 74 ?? 48 8b bd 30 ff ff ff e8 a0 41 00 00 0f 57 c0 0f 29 85 20 ff ff ff 48 c7 85 30 ff ff ff 00 00 00 00 66 c7 85 20 ff ff ff 02 67 c6 85 22 ff ff ff 00 48 ?? ?? ?? ?? ?? ?? ba 01 00 00 00 4c 89 ee e8 55 41 00 00 f6 85 20 ff ff ff 01 } //1
		$a_03_1 = {55 48 89 e5 41 57 41 56 41 54 53 48 83 ec 60 0f 57 c0 0f 29 45 a0 48 c7 45 b0 00 00 00 00 4c ?? ?? ?? 0f 29 45 c0 48 c7 45 d0 00 00 00 00 66 c7 45 c0 02 64 c6 45 c2 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}