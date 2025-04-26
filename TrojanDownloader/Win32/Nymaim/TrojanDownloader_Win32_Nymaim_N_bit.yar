
rule TrojanDownloader_Win32_Nymaim_N_bit{
	meta:
		description = "TrojanDownloader:Win32/Nymaim.N!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {0f b6 04 33 80 3d ?? ?? ?? 00 73 0f 84 a3 f3 ff ff 89 d1 c1 ea 19 c1 e1 07 01 ca 31 c2 43 83 3d ?? ?? ?? 00 00 } //1
		$a_03_1 = {89 4d f4 e8 ?? ?? ?? 00 32 06 46 88 07 47 ff 4d 10 75 f0 } //1
		$a_03_2 = {68 a5 cc e9 65 e8 ?? ?? ?? ff 8b 4c 24 10 66 39 04 71 74 19 68 a7 cc e9 65 e8 ?? ?? ?? ff 8b 4c 24 10 66 39 04 71 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}