
rule TrojanDownloader_Win64_RookIE_A_MTB{
	meta:
		description = "TrojanDownloader:Win64/RookIE.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {4c 8d 8c 24 60 04 00 00 41 b8 ff 03 00 00 48 8d 54 24 30 48 8b cf ff 15 90 01 01 40 01 00 44 8b 84 24 60 04 00 00 48 8d 54 24 30 48 63 cb 48 03 ce e8 90 01 01 38 00 00 8b 84 24 60 04 00 00 03 d8 85 c0 75 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}