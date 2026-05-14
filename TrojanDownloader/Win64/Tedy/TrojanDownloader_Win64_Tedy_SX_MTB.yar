
rule TrojanDownloader_Win64_Tedy_SX_MTB{
	meta:
		description = "TrojanDownloader:Win64/Tedy.SX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 03 00 00 "
		
	strings :
		$a_01_0 = {0f 29 84 24 90 00 00 00 33 c0 c7 84 24 a4 00 00 00 00 00 00 00 0f 10 06 0f 11 84 24 90 00 00 00 f3 0f 7e 46 10 66 0f d6 84 24 a0 00 00 00 c7 46 10 00 00 00 00 c7 46 14 07 00 00 00 66 89 06 } //20
		$a_80_1 = {5c 5a 68 69 4d 61 53 6b 69 6e 33 36 30 2e 65 78 65 } //\ZhiMaSkin360.exe  5
		$a_80_2 = {5a 68 69 4d 61 55 70 64 61 74 65 2e 64 6c 6c } //ZhiMaUpdate.dll  5
	condition:
		((#a_01_0  & 1)*20+(#a_80_1  & 1)*5+(#a_80_2  & 1)*5) >=30
 
}