
rule TrojanDownloader_BAT_Tiny_RC_MTB{
	meta:
		description = "TrojanDownloader:BAT/Tiny.RC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,18 00 18 00 05 00 00 0a 00 "
		
	strings :
		$a_02_0 = {06 09 07 09 1e d8 1e 6f 90 01 03 0a 18 28 90 01 03 0a 9c 09 17 d6 0d 09 11 04 31 e4 90 00 } //05 00 
		$a_80_1 = {6e 6f 68 69 6e 67 } //nohing  03 00 
		$a_80_2 = {41 64 65 72 72 72 72 72 72 72 72 72 72 72 72 72 72 72 72 72 72 6f 6f 6f 6f 6f 6f 6f 6f 6f 6f 6c 6c 6c } //Aderrrrrrrrrrrrrrrrrroooooooooolll  03 00 
		$a_80_3 = {5b 5e 30 31 5d } //[^01]  03 00 
		$a_80_4 = {77 65 62 43 6c 69 65 6e 74 } //webClient  00 00 
	condition:
		any of ($a_*)
 
}