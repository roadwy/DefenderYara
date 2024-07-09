
rule TrojanDownloader_Win32_PurpleFox_A_MTB{
	meta:
		description = "TrojanDownloader:Win32/PurpleFox.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {57 ff d6 68 ?? ?? ?? ?? 8b f8 ff 15 ?? ?? ?? ?? ff d6 2b c7 5f 3d ?? ?? ?? ?? 5e 0f 9c c0 } //2
		$a_03_1 = {57 ff d6 bf ?? ?? ?? ?? 8b d8 57 ff 15 ?? ?? ?? ?? ff d6 2b c3 3b c7 5f 5e 5b 0f 9c c0 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=2
 
}