
rule TrojanDownloader_Win64_DCRat_E_MTB{
	meta:
		description = "TrojanDownloader:Win64/DCRat.E!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {c6 44 24 38 00 48 c7 44 24 20 00 00 00 00 45 33 c9 4c 8d 44 24 30 33 c9 ff 15 ?? ?? 00 00 c7 44 24 28 00 00 00 00 48 c7 44 24 20 00 00 00 00 45 33 c9 4c 8d 05 96 20 00 00 48 8d 15 9b 20 00 00 33 c9 ff 15 ?? ?? 00 00 b9 23 00 00 00 ff 15 ?? ?? 00 00 66 85 c0 75 ?? b9 01 00 00 00 ff 15 ?? ?? 00 00 b9 ?? 00 00 00 ff 15 ?? ?? 00 00 66 85 c0 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}