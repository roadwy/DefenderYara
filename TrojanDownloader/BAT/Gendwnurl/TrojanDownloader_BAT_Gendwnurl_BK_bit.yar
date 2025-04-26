
rule TrojanDownloader_BAT_Gendwnurl_BK_bit{
	meta:
		description = "TrojanDownloader:BAT/Gendwnurl.BK!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {68 74 74 70 3a 2f 2f 63 6b 70 65 74 63 68 65 6d 2e 63 6f 6d [0-10] 2e 74 78 74 } //1
		$a_03_1 = {6c 00 6f 00 61 00 64 00 [0-10] 65 00 6e 00 74 00 72 00 79 00 70 00 6f 00 69 00 6e 00 74 00 [0-10] 69 00 6e 00 76 00 6f 00 6b 00 65 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}