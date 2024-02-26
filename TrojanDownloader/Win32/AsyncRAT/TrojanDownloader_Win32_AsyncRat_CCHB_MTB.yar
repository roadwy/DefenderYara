
rule TrojanDownloader_Win32_AsyncRat_CCHB_MTB{
	meta:
		description = "TrojanDownloader:Win32/AsyncRat.CCHB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {83 c4 08 eb 90 01 01 c7 45 e0 90 01 04 c7 45 e4 90 01 04 8b 55 e4 52 8b 45 e0 50 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}