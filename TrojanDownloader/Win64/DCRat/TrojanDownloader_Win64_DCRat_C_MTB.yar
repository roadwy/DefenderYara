
rule TrojanDownloader_Win64_DCRat_C_MTB{
	meta:
		description = "TrojanDownloader:Win64/DCRat.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 33 c4 48 89 45 f0 48 8d 15 ?? ?? 00 00 33 c9 ff 15 ?? 1f 00 00 48 8d 0d ?? 21 00 00 ff 15 ?? ?? 00 00 4c 8b f0 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}