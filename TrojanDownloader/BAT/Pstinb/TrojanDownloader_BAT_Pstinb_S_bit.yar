
rule TrojanDownloader_BAT_Pstinb_S_bit{
	meta:
		description = "TrojanDownloader:BAT/Pstinb.S!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 70 61 73 74 65 62 69 6e 2e 63 6f 6d 2f 72 61 77 } //1 http://pastebin.com/raw
		$a_01_1 = {61 64 64 5f 4c 6f 61 64 00 44 6f 77 6e 6c 6f 61 64 53 74 72 69 6e 67 00 41 70 70 44 6f 6d 61 69 6e 00 67 65 74 5f 43 75 72 72 65 6e 74 44 6f 6d 61 69 6e 00 43 6f 6e 76 65 72 74 00 46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}