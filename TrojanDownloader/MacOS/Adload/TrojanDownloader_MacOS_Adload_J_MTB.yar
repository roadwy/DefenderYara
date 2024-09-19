
rule TrojanDownloader_MacOS_Adload_J_MTB{
	meta:
		description = "TrojanDownloader:MacOS/Adload.J!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {c6 45 c2 00 48 ?? ?? ?? ba 01 00 00 00 4c 89 f6 e8 aa 09 00 00 f6 45 c0 01 74 ?? 48 8b 7d d0 e8 ad 09 00 00 0f 57 c0 0f 29 45 c0 } //1
		$a_03_1 = {ff 15 45 5e 00 00 41 f6 c7 01 49 0f 44 dd 4c 89 f7 48 8b 35 7b 5f 00 00 48 89 da 48 89 c1 ff 15 27 5e 00 00 48 89 c7 e8 3d 3e 00 00 48 89 c3 f6 85 20 ff ff ff 01 0f ?? ?? ?? ?? ?? f6 85 e8 fe ff ff 01 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}