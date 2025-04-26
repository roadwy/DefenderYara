
rule TrojanDownloader_Win32_Renos_PB{
	meta:
		description = "TrojanDownloader:Win32/Renos.PB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {80 74 10 ff 2b [0-08] a1 ?? ?? ?? ?? 8b 55 f8 8a 44 10 ff 8b 55 fc 8b 4d f4 88 04 0a ff 45 f4 81 7d f8 ?? ?? ?? ?? 0f 86 ?? ?? ff ff } //1
		$a_03_1 = {30 4c 10 ff [0-02] a1 ?? ?? ?? ?? 8b 55 f8 8a 44 10 ff 8b 55 fc 8b 4d f4 88 04 0a ff 45 f4 81 7d f8 ?? ?? ?? ?? 0f 86 ?? ?? ff ff } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}