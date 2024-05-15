
rule TrojanDownloader_BAT_FormBook_F_MTB{
	meta:
		description = "TrojanDownloader:BAT/FormBook.F!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {11 04 11 00 11 02 11 00 91 20 } //02 00 
		$a_01_1 = {06 59 d2 9c 20 } //02 00 
		$a_01_2 = {02 16 25 13 01 7d } //00 00  ᘂጥ紁
	condition:
		any of ($a_*)
 
}