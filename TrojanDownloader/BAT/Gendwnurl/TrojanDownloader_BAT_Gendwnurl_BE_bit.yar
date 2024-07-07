
rule TrojanDownloader_BAT_Gendwnurl_BE_bit{
	meta:
		description = "TrojanDownloader:BAT/Gendwnurl.BE!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {6a 00 62 00 64 00 73 00 69 00 63 00 6f 00 69 00 6f 00 } //1 jbdsicoio
		$a_03_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 69 00 6d 00 67 00 2d 00 73 00 61 00 76 00 65 00 2e 00 78 00 79 00 7a 00 90 02 20 2e 00 65 00 78 00 65 00 90 00 } //1
		$a_01_2 = {48 00 4b 00 45 00 59 00 5f 00 43 00 55 00 52 00 52 00 45 00 4e 00 54 00 5f 00 55 00 53 00 45 00 52 00 5c 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 43 00 6c 00 61 00 73 00 73 00 65 00 73 00 5c 00 73 00 74 00 65 00 61 00 6d 00 5c 00 53 00 68 00 65 00 6c 00 6c 00 5c 00 4f 00 70 00 65 00 6e 00 5c 00 43 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 } //1 HKEY_CURRENT_USER\Software\Classes\steam\Shell\Open\Command
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}