
rule TrojanDownloader_Win32_XWorm_CBV_MTB{
	meta:
		description = "TrojanDownloader:Win32/XWorm.CBV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {c7 45 cc 6b 65 72 6e c7 45 d0 65 6c 33 32 c7 45 d4 2e 64 6c 6c c6 45 d8 00 ff } //1
		$a_01_1 = {c7 45 bc 56 69 72 74 c7 45 c0 75 61 6c 41 c7 45 c4 6c 6c 6f 63 c6 45 c8 00 ff } //1
		$a_01_2 = {c7 45 dc 68 74 74 70 c7 45 e0 73 3a 2f 2f c7 45 e4 70 61 73 74 c7 45 e8 65 2e 65 65 c7 45 ec 2f 72 2f 59 c7 45 f0 36 72 6b 66 c7 45 } //1
		$a_01_3 = {68 74 74 70 73 3a 2f 2f 70 61 73 74 65 2e 65 65 2f 72 2f 59 36 72 6b 66 } //1 https://paste.ee/r/Y6rkf
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}