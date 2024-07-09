
rule TrojanDownloader_Win32_Banload_BFX{
	meta:
		description = "TrojanDownloader:Win32/Banload.BFX,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {54 61 62 4f 72 64 65 72 ?? ?? ?? 54 65 78 74 ?? ?? 68 74 74 70 [0-01] 3a 2f 2f } //1
		$a_03_1 = {83 c0 50 e8 ?? ?? ?? ?? 6a 00 b9 bf 28 00 00 ba ?? ?? ?? ?? 8b 83 ?? ?? 00 00 } //1
		$a_03_2 = {84 c0 74 05 e8 ?? ?? ?? ?? e8 ?? ?? ff ff 33 c0 e8 ?? ?? ff ff 84 c0 0f 84 ?? ?? 00 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=2
 
}