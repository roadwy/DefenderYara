
rule TrojanDownloader_Win32_Phorpiex_AH_MTB{
	meta:
		description = "TrojanDownloader:Win32/Phorpiex.AH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 02 00 00 "
		
	strings :
		$a_01_0 = {ba 70 00 00 00 66 89 95 26 f9 ff ff b8 3a 00 00 00 66 89 85 28 f9 ff ff b9 2f 00 00 00 66 89 8d 2a f9 ff ff ba 2f 00 00 00 } //30
		$a_01_1 = {c6 85 a1 fd ff ff 32 c6 85 a2 fd ff ff 2e c6 85 a3 fd ff ff 64 c6 85 a4 fd ff ff 6c c6 85 a5 fd ff ff 6c c6 85 a6 fd ff ff 00 } //20
	condition:
		((#a_01_0  & 1)*30+(#a_01_1  & 1)*20) >=50
 
}