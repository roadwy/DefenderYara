
rule TrojanDownloader_Win32_Upatre_BE{
	meta:
		description = "TrojanDownloader:Win32/Upatre.BE,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {66 ad 66 85 c0 74 f9 83 c4 0c 8b fe eb 1e 3c 00 75 b2 fe c0 04 2e fe c0 66 ab 8b 45 cc 33 c9 8b f0 41 eb 85 } //1
		$a_01_1 = {b9 bb 01 00 00 85 c0 75 05 b9 50 00 00 00 51 8b 45 ec ff 55 24 8a cc ff 55 20 50 ff 75 3c ff 93 44 11 00 00 59 85 c0 e1 cd } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}