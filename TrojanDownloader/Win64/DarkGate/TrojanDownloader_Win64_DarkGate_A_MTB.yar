
rule TrojanDownloader_Win64_DarkGate_A_MTB{
	meta:
		description = "TrojanDownloader:Win64/DarkGate.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b6 0c 13 44 0f b6 04 03 44 88 04 13 48 83 c2 90 01 01 88 0c 03 48 83 e8 90 00 } //2
		$a_03_1 = {44 0f b6 0c 01 48 83 c2 90 01 01 44 88 4a 90 01 01 44 88 04 01 48 83 e8 90 01 01 45 89 d0 41 29 c0 41 39 c0 90 00 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}