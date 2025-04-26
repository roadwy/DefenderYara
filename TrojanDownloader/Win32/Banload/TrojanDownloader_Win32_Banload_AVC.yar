
rule TrojanDownloader_Win32_Banload_AVC{
	meta:
		description = "TrojanDownloader:Win32/Banload.AVC,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {66 b8 44 00 e8 ?? ?? ?? ?? 6a 00 6a 00 6a 00 6a 00 8b 45 ?? e8 ?? ?? ?? ?? 50 e8 } //1
		$a_03_1 = {66 b8 44 00 e8 ?? ?? ?? ?? 8b 45 f8 e8 ?? ?? ?? ?? 50 6a 00 e8 ?? ?? ?? ?? 83 f8 20 0f 97 c3 33 c0 } //1
		$a_03_2 = {bf 00 01 00 00 66 83 eb 43 74 0e 66 ff cb 0f 84 ?? ?? ?? ?? e9 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}