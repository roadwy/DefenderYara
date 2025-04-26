
rule TrojanDownloader_Win64_DCRat_H_MTB{
	meta:
		description = "TrojanDownloader:Win64/DCRat.H!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 d2 8d 4a 02 ff 15 ?? 2b 00 00 48 8b f0 c7 85 c0 01 00 00 38 02 00 00 48 8d 95 c0 01 00 00 48 8b c8 ff 15 ?? 2b 00 00 85 c0 0f ?? ?? ?? ?? ?? 48 8d 85 ec 01 00 00 49 8b cf 66 0f 1f 44 00 00 48 ff c1 66 83 3c 48 00 75 ?? 48 8b c3 48 83 7b 18 08 72 ?? 48 8b 03 4c 8b 43 10 4c 3b c1 75 ?? 48 8d 95 ec 01 00 00 4d 85 c0 74 ?? 0f 1f 40 00 0f b7 0a 66 39 08 75 ?? 48 83 c0 02 48 83 c2 02 49 83 e8 01 75 ea 44 8b 85 c8 01 00 00 33 d2 8d 4a 01 ff 15 ?? 2b 00 00 48 8b f8 48 85 c0 74 ?? 33 d2 48 8b c8 ff 15 ?? 2b 00 00 48 8b cf ff ?? 6c 2b 00 00 48 8d 95 c0 01 00 00 48 8b ce ff 15 ?? 2b 00 00 85 c0 0f } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}