
rule TrojanDownloader_Win32_Renos_JU{
	meta:
		description = "TrojanDownloader:Win32/Renos.JU,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {66 0f be 05 ?? ?? ?? ?? 66 0f af 05 ?? ?? ?? ?? 66 a3 ?? ?? ?? ?? 33 c0 39 44 24 04 75 ?? 39 05 } //1
		$a_01_1 = {8d 85 b8 d3 ff ff 56 50 8d 45 b8 6a 18 50 68 00 14 2d 00 ff 75 e8 ff 15 } //1
		$a_03_2 = {c7 45 d4 4c 1d 00 00 01 05 ?? ?? ?? ?? 8d 45 d4 50 6a 02 56 ff 15 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}