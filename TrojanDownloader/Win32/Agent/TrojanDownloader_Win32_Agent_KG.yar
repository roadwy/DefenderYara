
rule TrojanDownloader_Win32_Agent_KG{
	meta:
		description = "TrojanDownloader:Win32/Agent.KG,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {2e 74 78 74 00 } //1
		$a_03_1 = {68 13 00 00 20 8b ce c7 ?? ?? 04 00 00 00 e8 ?? ?? 00 00 85 c0 0f ?? ?? 00 00 00 8b 45 ?? 3d c8 00 00 00 0f ?? ?? 00 00 00 3d 2c 01 00 00 0f ?? ?? 00 00 00 } //1
		$a_03_2 = {8b 16 8b ce ff 52 54 85 f6 74 09 8b 06 6a 01 8b ce ff 50 04 8d 4d bc e8 ?? ?? 00 00 8b 4d e8 6a 03 51 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}