
rule TrojanDownloader_Win32_Rugmi_KK_MTB{
	meta:
		description = "TrojanDownloader:Win32/Rugmi.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 4c 24 10 8b 44 24 14 8b c3 0f b7 c9 99 33 cd f7 fe 8b c1 89 8c 3c 9c 06 00 00 8b 4c 24 10 8b 74 24 14 89 94 3c ac 2d 00 00 99 03 c1 89 44 24 10 13 d6 81 c3 69 7a 00 00 83 c7 04 89 54 24 14 45 be e8 03 00 00 83 6c 24 28 01 75 b3 } //10
		$a_01_1 = {69 c3 01 00 01 00 8b 4c 24 10 8b 74 24 14 03 c7 99 f7 fd 8b da 8b c2 99 33 c1 33 d6 47 89 44 24 10 89 54 24 14 81 ff 8c 00 00 00 7c d3 } //20
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*20) >=30
 
}