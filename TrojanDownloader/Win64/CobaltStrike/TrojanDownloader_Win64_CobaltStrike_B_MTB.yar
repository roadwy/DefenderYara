
rule TrojanDownloader_Win64_CobaltStrike_B_MTB{
	meta:
		description = "TrojanDownloader:Win64/CobaltStrike.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {f7 f9 8b c2 48 98 0f be 44 04 90 01 01 8b 4c 24 54 33 c8 8b c1 90 00 } //2
		$a_03_1 = {41 f7 e9 41 8b c9 41 ff c1 8b c2 c1 e8 90 01 01 03 d0 8d 04 52 2b c8 48 63 c1 0f b6 4c 04 90 01 01 41 30 4a 90 01 01 49 63 c1 48 3b c3 90 00 } //2
		$a_03_2 = {48 63 c8 0f b6 44 0c 90 01 01 41 30 00 ff c2 49 ff c0 48 63 c2 48 3b c3 90 00 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_03_2  & 1)*2) >=2
 
}