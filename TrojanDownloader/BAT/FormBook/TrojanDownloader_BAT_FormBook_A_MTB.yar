
rule TrojanDownloader_BAT_FormBook_A_MTB{
	meta:
		description = "TrojanDownloader:BAT/FormBook.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 0d 08 09 16 73 ?? 00 00 0a 13 04 11 04 02 7b ?? 00 00 04 6f ?? 00 00 0a 02 7b ?? 00 00 04 6f ?? 00 00 0a 13 05 dd } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}