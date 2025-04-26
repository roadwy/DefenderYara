
rule TrojanDownloader_Win64_AsyncRat_CCIQ_MTB{
	meta:
		description = "TrojanDownloader:Win64/AsyncRat.CCIQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 81 c7 5d 7a 17 48 57 5f 49 31 38 eb 0b 56 5e } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}