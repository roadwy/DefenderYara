
rule TrojanDownloader_Win64_TwoDash_A_dha{
	meta:
		description = "TrojanDownloader:Win64/TwoDash.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,64 00 64 00 01 00 00 "
		
	strings :
		$a_43_0 = {c9 fd 43 03 00 81 c1 c3 9e 26 00 8b c1 c1 e8 18 30 82 90 01 04 42 81 fa 90 01 04 72 90 00 00 } //100
	condition:
		((#a_43_0  & 1)*100) >=100
 
}