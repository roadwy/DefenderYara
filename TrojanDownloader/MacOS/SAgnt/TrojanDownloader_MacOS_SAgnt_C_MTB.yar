
rule TrojanDownloader_MacOS_SAgnt_C_MTB{
	meta:
		description = "TrojanDownloader:MacOS/SAgnt.C!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_00_0 = {30 60 30 50 10 50 20 10 20 20 10 40 20 30 20 10 50 20 20 30 30 20 10 40 20 30 50 40 30 40 d0 07 b0 03 d0 03 70 80 04 d0 07 80 04 c0 03 d0 03 c0 03 b0 03 d0 03 b0 03 c0 03 c0 03 e0 3a a0 03 c0 } //00 00 
	condition:
		any of ($a_*)
 
}