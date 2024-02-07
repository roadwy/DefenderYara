
rule Trojan_BAT_Downloader_SRX_MTB{
	meta:
		description = "Trojan:BAT/Downloader.SRX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 01 00 "
		
	strings :
		$a_81_0 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //02 00  FromBase64String
		$a_81_1 = {70 72 30 74 33 5f 64 65 63 72 79 70 74 } //01 00  pr0t3_decrypt
		$a_81_2 = {67 65 74 5f 43 68 61 72 73 } //01 00  get_Chars
		$a_81_3 = {53 74 72 52 65 76 65 72 73 65 } //00 00  StrReverse
	condition:
		any of ($a_*)
 
}