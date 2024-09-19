
rule TrojanDownloader_Win64_DCRat_F_MTB{
	meta:
		description = "TrojanDownloader:Win64/DCRat.F!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 03 00 00 "
		
	strings :
		$a_03_0 = {48 0f 47 54 24 50 48 c7 44 24 20 00 00 00 00 45 33 c9 33 c9 ff 15 ?? ?? ?? 00 c7 44 24 28 00 00 00 00 48 c7 44 24 20 00 00 00 00 45 33 c9 4c 8d 05 ?? ?? ?? 00 48 8d 15 ?? ?? ?? 00 33 c9 ff 15 } //4
		$a_03_1 = {b9 23 00 00 00 ff 15 ?? ?? ?? 00 66 85 c0 75 } //2
		$a_03_2 = {b9 01 00 00 00 ff 15 ?? ?? ?? 00 b9 23 00 00 00 ff 15 } //2
	condition:
		((#a_03_0  & 1)*4+(#a_03_1  & 1)*2+(#a_03_2  & 1)*2) >=8
 
}