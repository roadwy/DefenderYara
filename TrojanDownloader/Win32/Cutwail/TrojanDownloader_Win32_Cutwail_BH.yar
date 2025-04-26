
rule TrojanDownloader_Win32_Cutwail_BH{
	meta:
		description = "TrojanDownloader:Win32/Cutwail.BH,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {81 e1 ff ff 00 00 81 f9 19 04 00 00 75 07 b8 01 00 00 00 eb 04 eb d1 } //1
		$a_03_1 = {0f b6 42 03 83 f0 ?? 8b 4d 08 03 4d fc 88 41 03 eb } //1
		$a_03_2 = {81 3a 43 6d 64 4c 75 14 8b 45 ?? 81 78 04 69 6e 65 3a } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}