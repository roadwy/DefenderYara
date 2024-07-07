
rule TrojanDownloader_BAT_Seraph_ARBD_MTB{
	meta:
		description = "TrojanDownloader:BAT/Seraph.ARBD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {08 09 18 5b 06 09 18 6f 17 00 00 0a 1f 10 28 18 00 00 0a 9c 09 18 58 0d 09 07 32 e4 } //5
		$a_80_1 = {68 74 74 70 3a 2f 2f 6d 6f 73 69 61 64 6f 6d 6e 65 61 73 63 61 2e 72 6f 2f 77 70 2d 69 6e 63 6c 75 64 65 73 2f } //http://mosiadomneasca.ro/wp-includes/  5
	condition:
		((#a_01_0  & 1)*5+(#a_80_1  & 1)*5) >=10
 
}