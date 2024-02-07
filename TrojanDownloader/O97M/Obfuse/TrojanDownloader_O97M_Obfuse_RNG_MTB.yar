
rule TrojanDownloader_O97M_Obfuse_RNG_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.RNG!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {52 61 6e 67 65 28 22 41 31 3a 4a 31 35 22 29 2e 53 65 6c 65 63 74 } //01 00  Range("A1:J15").Select
		$a_01_1 = {52 61 6e 67 65 28 22 6c 31 3a 78 32 32 22 29 2e 53 65 6c 65 63 74 } //01 00  Range("l1:x22").Select
		$a_01_2 = {63 77 6a 6b 76 66 62 75 6d 73 67 6d 6a 69 70 73 62 64 61 6c 70 61 73 72 61 77 73 74 7a 6c 6d 77 70 63 6e 20 3d 20 52 61 6e 67 65 28 22 41 33 22 29 2e 56 61 6c 75 65 } //01 00  cwjkvfbumsgmjipsbdalpasrawstzlmwpcn = Range("A3").Value
		$a_01_3 = {53 65 74 20 69 6e 62 79 6b 77 6d 63 70 20 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 52 61 6e 67 65 28 22 41 34 22 29 2e 56 61 6c 75 65 29 } //01 00  Set inbykwmcp  = CreateObject(Range("A4").Value)
		$a_01_4 = {62 6e 74 6e 67 71 72 70 77 20 3d 20 69 6e 62 79 6b 77 6d 63 70 2e 43 72 65 61 74 65 28 63 77 6a 6b 76 66 62 75 6d 73 67 6d 6a 69 70 73 62 64 61 6c 70 61 73 72 61 77 73 74 7a 6c 6d 77 70 63 6e 29 } //00 00  bntngqrpw = inbykwmcp.Create(cwjkvfbumsgmjipsbdalpasrawstzlmwpcn)
	condition:
		any of ($a_*)
 
}