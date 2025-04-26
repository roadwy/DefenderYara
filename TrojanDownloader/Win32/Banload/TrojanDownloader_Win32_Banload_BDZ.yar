
rule TrojanDownloader_Win32_Banload_BDZ{
	meta:
		description = "TrojanDownloader:Win32/Banload.BDZ,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {0f b6 17 32 55 10 88 17 81 fe ?? ?? ?? ?? 7d ?? be ?? ?? ?? ?? 40 49 75 } //1
		$a_03_1 = {0f b7 5c 70 fe 33 5d ?? 3b fb 7c ?? 81 c3 ff 00 00 00 2b df eb 02 } //1
		$a_03_2 = {0f b6 09 32 4d 10 8b 5d 08 03 da 88 0b 3b 45 ?? 7e 02 8b f0 3b f0 7d 03 89 75 ?? 42 ff 4d ?? 75 da } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=2
 
}