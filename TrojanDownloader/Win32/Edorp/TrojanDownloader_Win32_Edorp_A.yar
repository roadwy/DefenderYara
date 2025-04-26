
rule TrojanDownloader_Win32_Edorp_A{
	meta:
		description = "TrojanDownloader:Win32/Edorp.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {c7 44 24 08 3f 00 0f 00 a1 ?? ?? ?? ?? 8b 84 85 ?? ?? ff ff 89 44 24 04 8b 45 f4 89 04 24 e8 ?? ?? ?? ?? 83 ec 0c 89 45 f0 } //1
		$a_03_1 = {8d 85 78 ff ff ff 89 44 24 08 a1 ?? ?? ?? ?? 8b 04 85 ?? ?? ?? ?? 89 44 24 04 8d 85 68 ff ff ff 89 04 24 c7 85 28 ff ff ff 12 00 00 00 e8 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}