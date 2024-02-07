
rule Trojan_BAT_LokiBot_NUX_MTB{
	meta:
		description = "Trojan:BAT/LokiBot.NUX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {57 5f a2 c9 09 0b 00 00 00 fa 25 33 00 16 00 00 02 00 00 00 88 00 00 00 19 00 00 00 56 00 00 00 c4 01 00 00 ab 00 00 00 03 00 00 00 e9 00 00 00 02 00 00 00 95 } //01 00 
		$a_01_1 = {24 39 65 37 31 39 30 63 32 2d 31 66 35 65 2d 34 61 66 61 2d 62 61 30 39 2d 38 61 63 39 39 36 65 61 36 64 37 62 } //01 00  $9e7190c2-1f5e-4afa-ba09-8ac996ea6d7b
		$a_01_2 = {54 79 70 69 6e 67 47 61 6d 65 2e 46 6f 72 6d 31 } //00 00  TypingGame.Form1
	condition:
		any of ($a_*)
 
}