
rule TrojanDownloader_Win32_REntS_SIBJ_MTB{
	meta:
		description = "TrojanDownloader:Win32/REntS.SIBJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {29 c3 9f 88 e0 aa bb 90 01 04 d1 c3 ba 90 01 04 b9 90 01 04 d3 ca ba 90 01 04 b9 90 01 04 d3 ca ba 90 01 04 b9 90 01 04 d3 c2 ba 90 01 04 42 9f 88 27 47 b8 90 01 04 48 ba 90 01 04 b9 90 01 04 d3 ca 9f 88 e0 aa bb 90 01 04 81 eb 90 01 04 9c 5a 88 17 47 ba 90 01 04 d1 c2 ba 90 01 04 4a 9c 5a 88 17 47 bb 90 01 04 b9 90 01 04 d3 c3 bb 90 01 04 43 9f 88 27 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}