
rule TrojanDownloader_Win32_REntS_SIBH_MTB{
	meta:
		description = "TrojanDownloader:Win32/REntS.SIBH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {d3 ca 9c 59 88 0f 47 b9 90 01 04 49 bb 90 01 04 d1 c3 9c 58 aa b8 90 01 04 c1 f8 90 01 01 bb 90 01 04 43 9f 86 c4 aa bb 90 01 04 b9 90 01 04 d3 cb bb 90 01 04 d1 c3 bb 90 01 04 4b 9f 88 27 47 ba 90 01 04 c1 f2 90 01 01 ba 90 01 04 42 9c 58 aa ba 90 01 04 d1 f2 bb 90 01 04 4b 9f 88 27 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}