
rule TrojanDownloader_Win32_Renos_gen_BD{
	meta:
		description = "TrojanDownloader:Win32/Renos.gen!BD,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {c7 45 e0 4f 00 00 00 c7 45 e4 86 f3 00 00 } //01 00 
		$a_01_1 = {8b 45 e0 cd 41 66 3b 45 e4 0f 94 c0 0f b6 c0 89 45 dc } //01 00 
		$a_01_2 = {c7 85 80 fd ff ff 68 58 4d 56 c7 85 7c fd ff ff 58 56 00 00 } //01 00 
		$a_01_3 = {8b 85 80 fd ff ff 66 8b 95 7c fd ff ff ed 3b 9d 80 fd ff ff 0f 94 c0 0f b6 c0 } //02 00 
		$a_01_4 = {81 f2 bd 00 00 00 88 14 01 41 eb } //02 00 
		$a_01_5 = {83 f0 62 88 04 3e 46 eb } //00 00 
	condition:
		any of ($a_*)
 
}