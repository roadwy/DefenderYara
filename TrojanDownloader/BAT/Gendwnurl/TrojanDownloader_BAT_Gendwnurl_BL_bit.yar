
rule TrojanDownloader_BAT_Gendwnurl_BL_bit{
	meta:
		description = "TrojanDownloader:BAT/Gendwnurl.BL!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {73 00 63 00 72 00 65 00 65 00 6e 00 73 00 68 00 6f 00 74 00 } //1 screenshot
		$a_01_1 = {73 00 79 00 73 00 74 00 65 00 6d 00 69 00 6e 00 66 00 6f 00 } //1 systeminfo
		$a_01_2 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 63 00 32 00 2e 00 68 00 6f 00 77 00 69 00 65 00 6c 00 61 00 62 00 2e 00 63 00 6f 00 6d 00 2f 00 43 00 32 00 2f 00 43 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 } //1 http://c2.howielab.com/C2/Command
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}