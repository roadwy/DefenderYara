
rule TrojanDownloader_Win64_CobaltStrike_GLG_MTB{
	meta:
		description = "TrojanDownloader:Win64/CobaltStrike.GLG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {2f 00 72 00 65 00 76 00 2e 00 61 00 65 00 73 00 } //1 /rev.aes
		$a_01_1 = {33 00 38 00 2e 00 32 00 30 00 37 00 2e 00 31 00 37 00 36 00 2e 00 38 00 36 00 } //1 38.207.176.86
		$a_01_2 = {6c 65 61 73 65 5c 50 72 6f 6a 65 63 74 35 2e 70 64 62 } //1 lease\Project5.pdb
		$a_01_3 = {55 00 73 00 65 00 72 00 2d 00 41 00 67 00 65 00 6e 00 74 00 3a 00 20 00 4d 00 6f 00 7a 00 69 00 6c 00 6c 00 61 00 2f 00 35 00 2e 00 30 00 20 00 28 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 4e 00 54 00 20 00 36 00 2e 00 33 00 3b 00 20 00 57 00 4f 00 57 00 36 00 34 00 29 00 } //1 User-Agent: Mozilla/5.0 (Windows NT 6.3; WOW64)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}