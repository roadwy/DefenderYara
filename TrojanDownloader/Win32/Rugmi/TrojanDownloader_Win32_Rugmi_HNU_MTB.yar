
rule TrojanDownloader_Win32_Rugmi_HNU_MTB{
	meta:
		description = "TrojanDownloader:Win32/Rugmi.HNU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_03_0 = {8b 78 08 8d 04 3b 89 45 ?? 8b 46 3c 8b 44 06 2c 89 } //5
		$a_01_1 = {c7 04 24 00 00 00 00 89 44 24 04 ff 15 } //1
		$a_03_2 = {89 04 24 ff d1 8d 65 ?? 59 5b 5e 5f 5d } //1
		$a_01_3 = {c7 44 24 0c 04 00 00 00 c7 } //1
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=8
 
}