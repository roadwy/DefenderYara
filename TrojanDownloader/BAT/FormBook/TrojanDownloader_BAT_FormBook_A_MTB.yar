
rule TrojanDownloader_BAT_FormBook_A_MTB{
	meta:
		description = "TrojanDownloader:BAT/FormBook.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {0a 0d 08 09 16 73 90 01 01 00 00 0a 13 04 11 04 02 7b 90 01 01 00 00 04 6f 90 01 01 00 00 0a 02 7b 90 01 01 00 00 04 6f 90 01 01 00 00 0a 13 05 dd 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}