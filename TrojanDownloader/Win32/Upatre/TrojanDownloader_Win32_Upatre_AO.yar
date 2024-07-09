
rule TrojanDownloader_Win32_Upatre_AO{
	meta:
		description = "TrojanDownloader:Win32/Upatre.AO,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {57 ab 33 c0 ab e2 fd 8b 7d ?? 57 ab ab ab ab 8b f8 } //1
		$a_01_1 = {03 f2 51 57 8b 06 59 33 c1 89 06 03 f2 59 47 e2 f1 } //2
		$a_12_2 = {3a 5c 54 45 4d 50 5c 90 02 06 2e 65 78 65 90 00 00 } //2
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*2+(#a_12_2  & 1)*2) >=5
 
}