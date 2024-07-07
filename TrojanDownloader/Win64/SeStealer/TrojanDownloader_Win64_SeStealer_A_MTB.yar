
rule TrojanDownloader_Win64_SeStealer_A_MTB{
	meta:
		description = "TrojanDownloader:Win64/SeStealer.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 8d 54 24 40 48 8b cd 44 89 7c 24 44 44 89 7c 24 40 ff 57 40 48 8d 4c 24 51 33 d2 41 b8 bb 02 00 00 44 88 7c 24 50 e8 90 01 04 4c 8d 4c 24 44 48 8d 54 24 50 41 b8 bc 02 00 00 48 8b cd ff 57 50 8b 5c 24 44 8b ce 48 8d 54 24 50 49 03 cc 90 00 } //2
		$a_01_1 = {49 ff c0 ff c1 41 30 40 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}