
rule TrojanDownloader_Win32_Beebone_gen_B{
	meta:
		description = "TrojanDownloader:Win32/Beebone.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,1f 00 1f 00 05 00 00 "
		
	strings :
		$a_01_0 = {00 00 63 00 6d 00 64 00 00 00 } //1
		$a_03_1 = {6d 00 64 00 90 09 04 00 04 00 00 00 } //1
		$a_03_2 = {53 48 47 65 74 46 6f 6c 64 65 72 50 61 74 68 57 (?? ?? ??|?? ?? ??) ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 53 68 65 6c 6c 45 78 65 63 75 74 65 57 00 } //20
		$a_03_3 = {89 45 b4 8b 0d ?? ?? ?? ?? 51 ff 15 ?? ?? ?? ?? 89 45 b0 6a 00 6a 00 8b 55 b0 52 8b 45 b4 50 6a 00 6a 00 e8 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? c7 45 fc ?? 00 00 00 90 09 12 00 c7 45 fc ?? 00 00 00 68 ?? ?? ?? ?? ff 15 } //10
		$a_03_4 = {89 45 c8 ff 35 ?? ?? ?? ?? e8 ?? ?? ff ff 89 45 c4 6a 00 6a 00 ff 75 c4 ff 75 c8 6a 00 6a 00 e8 ?? ?? ff ff e8 ?? ?? ff ff 8d 4d dc e8 ?? ?? ff ff c7 45 fc 06 00 00 00 6a 01 } //10
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*20+(#a_03_3  & 1)*10+(#a_03_4  & 1)*10) >=31
 
}