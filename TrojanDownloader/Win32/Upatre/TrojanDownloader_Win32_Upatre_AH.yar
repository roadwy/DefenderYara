
rule TrojanDownloader_Win32_Upatre_AH{
	meta:
		description = "TrojanDownloader:Win32/Upatre.AH,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {2b 45 00 3d d0 07 00 00 76 ?? 89 45 04 89 45 44 8b 45 00 40 66 81 38 4e 5a } //1
		$a_00_1 = {68 80 00 00 00 6a 02 50 6a 02 68 00 00 00 40 8b 45 ec b4 04 ff 55 24 8a cc } //1
		$a_00_2 = {f3 a4 5e 51 68 80 00 00 00 6a 02 51 6a 02 68 00 00 00 40 ff 75 54 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}