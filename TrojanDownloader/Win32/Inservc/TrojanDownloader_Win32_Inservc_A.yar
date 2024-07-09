
rule TrojanDownloader_Win32_Inservc_A{
	meta:
		description = "TrojanDownloader:Win32/Inservc.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_00_0 = {6c 69 73 74 73 2e 78 6d 69 72 72 6f 72 2e 75 73 } //1 lists.xmirror.us
		$a_00_1 = {64 64 6c 2d 68 65 6c 70 2e 69 6e 66 6f } //1 ddl-help.info
		$a_03_2 = {7e f0 83 c4 f8 6a 00 6a 00 ff 75 14 8b b5 ?? ?? ff ff 56 8b 85 ?? ?? ff ff 50 6a 00 e8 ?? ?? 00 00 } //1
		$a_03_3 = {7e f0 83 c4 f8 8b b5 ?? ?? ff ff 56 8b 85 ?? ?? ff ff 50 e8 ?? ?? 00 00 83 c4 08 85 c0 75 17 83 c4 f4 6a 50 e8 ?? ?? 00 00 66 89 ?? ?? ?? ff ff 83 c4 0c eb 0c } //1
		$a_03_4 = {7e f0 83 c4 f8 8b 95 ?? ?? ff ff 52 53 e8 ?? ?? 00 00 89 c2 83 c4 10 85 d2 0f 84 ?? ?? 00 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1) >=3
 
}