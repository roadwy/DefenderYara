
rule TrojanDownloader_BAT_Gendwnurl_BN_bit{
	meta:
		description = "TrojanDownloader:BAT/Gendwnurl.BN!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 75 00 2e 00 6c 00 65 00 77 00 64 00 2e 00 73 00 65 00 2f 00 [0-20] 2e 00 65 00 78 00 65 00 } //1
		$a_02_1 = {41 00 70 00 70 00 64 00 61 00 74 00 61 00 [0-10] 2e 00 45 00 78 00 65 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}