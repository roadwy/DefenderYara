
rule TrojanDownloader_Win64_Tickler_B_dha{
	meta:
		description = "TrojanDownloader:Win64/Tickler.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_40_0 = {09 04 02 81 f7 e9 03 d1 c1 fa 06 8b c2 c1 e8 1f 03 d0 6b c2 7f 2b c8 43 88 0c 01 49 ff c0 4d 8d 52 04 49 81 f8 83 00 00 00 00 } //1
	condition:
		((#a_40_0  & 1)*1) >=1
 
}