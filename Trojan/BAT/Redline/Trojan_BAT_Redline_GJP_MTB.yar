
rule Trojan_BAT_Redline_GJP_MTB{
	meta:
		description = "Trojan:BAT/Redline.GJP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 0a 00 "
		
	strings :
		$a_01_0 = {16 10 01 02 1f 64 31 06 03 16 fe 01 2b 01 16 0c 08 2c 0a 72 25 0e 00 70 0b 17 10 01 00 00 03 0d 09 2c 04 07 0a 2b 04 14 0a 2b 00 06 2a } //01 00 
		$a_80_1 = {70 61 73 74 65 62 69 6e 2e 70 6c 2f 76 69 65 77 2f 72 61 77 2f 32 33 31 33 37 36 65 63 } //pastebin.pl/view/raw/231376ec  00 00 
	condition:
		any of ($a_*)
 
}