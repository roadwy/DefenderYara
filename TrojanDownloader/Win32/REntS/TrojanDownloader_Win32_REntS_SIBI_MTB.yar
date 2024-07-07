
rule TrojanDownloader_Win32_REntS_SIBI_MTB{
	meta:
		description = "TrojanDownloader:Win32/REntS.SIBI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {88 27 47 ba 90 01 04 b9 90 01 04 d3 e2 b9 90 01 04 41 b8 90 01 04 b9 90 01 04 d3 c8 9f 86 c4 aa ba 90 01 04 81 fa 90 01 04 b8 90 01 04 37 bb 90 01 04 4b 9c 58 aa b8 90 01 04 b9 90 01 04 29 c8 9f 88 27 47 bb 90 01 04 b8 90 01 04 29 c3 9f 88 e0 aa bb 90 01 04 d1 c3 ba 90 01 04 b9 90 01 04 d3 ca b8 90 01 04 d1 c0 b9 90 01 04 49 9f 88 27 47 bb 90 01 04 d1 f3 b8 90 01 04 40 9c 58 aa b8 90 01 04 b9 90 01 04 d3 c8 bb 90 01 04 b9 90 01 04 d3 c3 b8 90 01 04 d1 c0 bb 90 01 04 d1 c3 b8 90 01 04 b9 90 01 04 d3 c0 bb 90 01 04 b9 90 01 04 d3 c3 ba 90 01 04 b9 90 01 04 d3 ca bb 90 01 04 4b 9f 88 27 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}