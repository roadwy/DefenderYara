
rule TrojanDownloader_Win32_Waski_GNZ_MTB{
	meta:
		description = "TrojanDownloader:Win32/Waski.GNZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {80 f2 f1 c0 c2 03 80 ea 05 80 f2 03 56 } //10
		$a_01_1 = {8b 4c 24 0c 8b 5c 24 04 8b c3 03 c1 83 e8 01 8a 00 8b 54 24 08 03 d1 88 42 ff e2 ec c2 0c 00 } //10
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10) >=20
 
}