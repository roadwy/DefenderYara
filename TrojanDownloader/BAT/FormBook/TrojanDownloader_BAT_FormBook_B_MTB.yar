
rule TrojanDownloader_BAT_FormBook_B_MTB{
	meta:
		description = "TrojanDownloader:BAT/FormBook.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 13 04 73 ?? 00 00 0a 13 05 08 73 ?? 00 00 0a 13 06 11 06 11 04 16 73 ?? 00 00 0a 13 07 11 07 11 05 6f ?? 00 00 0a 11 05 6f ?? 00 00 0a 13 08 de } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}