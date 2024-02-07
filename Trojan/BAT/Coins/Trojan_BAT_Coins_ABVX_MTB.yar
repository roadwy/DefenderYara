
rule Trojan_BAT_Coins_ABVX_MTB{
	meta:
		description = "Trojan:BAT/Coins.ABVX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {0a 0d 07 09 6f 90 01 01 00 00 0a 08 6f 90 01 01 00 00 0a 2d ea dd 90 01 01 00 00 00 08 39 90 01 01 00 00 00 08 6f 90 01 01 00 00 0a dc 07 6f 90 01 01 00 00 0a 2a 90 00 } //01 00 
		$a_01_1 = {52 65 61 64 41 73 42 79 74 65 41 72 72 61 79 41 73 79 6e 63 } //01 00  ReadAsByteArrayAsync
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //00 00  FromBase64String
	condition:
		any of ($a_*)
 
}