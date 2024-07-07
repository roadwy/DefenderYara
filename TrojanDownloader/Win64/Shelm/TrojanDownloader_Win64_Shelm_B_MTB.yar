
rule TrojanDownloader_Win64_Shelm_B_MTB{
	meta:
		description = "TrojanDownloader:Win64/Shelm.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 8d 54 24 40 44 89 64 24 40 48 8b ce 44 89 64 24 44 ff 15 90 01 01 1f 00 00 85 c0 74 90 01 01 48 85 ff 75 90 01 01 8b 4c 24 40 83 c1 01 49 0f 42 cd ff 15 90 01 01 1f 00 00 eb 90 01 01 8b 54 24 40 48 8b cf 03 d3 83 c2 01 49 0f 42 d5 ff 15 90 01 01 1f 00 00 48 85 c0 74 90 01 01 44 8b 44 24 40 4c 8d 4c 24 44 8b d3 48 8b ce 48 03 d0 48 8b f8 ff 15 90 01 01 1f 00 00 85 c0 74 90 01 01 03 5c 24 44 44 39 64 24 40 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}