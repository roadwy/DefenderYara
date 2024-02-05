
rule TrojanDownloader_Win32_REntS_SIBG_MTB{
	meta:
		description = "TrojanDownloader:Win32/REntS.SIBG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {88 f8 24 01 d0 90 01 01 53 80 e7 90 01 01 00 f8 5b d0 90 01 01 53 80 e7 90 01 01 00 f8 5b c0 ef 90 01 01 80 e7 90 01 01 00 f8 5b 85 db 74 90 01 01 90 18 24 90 01 01 c0 e0 90 01 01 5b 00 d8 88 02 42 a1 90 01 04 05 90 01 04 39 c2 75 90 01 01 ff 25 90 00 } //01 00 
		$a_03_1 = {6a 40 68 00 10 00 00 68 90 01 04 6a 00 ff 15 90 01 04 a3 90 01 04 97 ba 90 01 04 d1 c2 ba 90 01 04 81 c2 90 01 04 b8 90 01 04 37 b8 90 01 04 40 9f 88 27 47 ba 90 01 04 d1 c2 ba 90 01 04 d1 e2 ba 90 01 04 b9 90 01 04 d3 fa bb 90 01 04 b9 90 01 04 d3 cb b8 90 01 04 81 c0 90 01 04 9c 5a 88 17 47 b8 90 01 04 c1 f0 a4 bb 90 01 04 43 9c 5a 88 17 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}