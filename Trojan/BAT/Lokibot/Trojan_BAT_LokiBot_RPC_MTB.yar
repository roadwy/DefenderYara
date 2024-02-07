
rule Trojan_BAT_LokiBot_RPC_MTB{
	meta:
		description = "Trojan:BAT/LokiBot.RPC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {20 16 08 02 00 0c 2b 13 00 06 08 20 00 01 00 00 28 07 00 00 06 0a 00 08 15 58 0c 08 16 fe 04 16 fe 01 0d 09 2d e2 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_LokiBot_RPC_MTB_2{
	meta:
		description = "Trojan:BAT/LokiBot.RPC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {00 06 07 06 6f 25 00 00 0a 5d 6f 26 00 00 0a 28 08 00 00 06 07 91 73 27 00 00 0a 0c 28 08 00 00 06 07 08 6f 28 00 00 0a 08 6f 29 00 00 0a 61 28 2a 00 00 0a 9c 00 07 17 58 0b 07 28 08 00 00 06 8e 69 fe 04 0d 09 2d b8 } //01 00 
		$a_01_1 = {32 00 34 00 59 00 38 00 47 00 59 00 44 00 51 00 32 00 4a 00 36 00 56 00 54 00 4a 00 42 00 } //00 00  24Y8GYDQ2J6VTJB
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_LokiBot_RPC_MTB_3{
	meta:
		description = "Trojan:BAT/LokiBot.RPC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {31 00 48 00 42 00 44 00 36 00 4c 00 48 00 30 00 39 00 4b 00 53 00 52 00 } //01 00  1HBD6LH09KSR
		$a_01_1 = {30 78 44 43 6f 6d 70 36 6c 65 73 } //01 00  0xDComp6les
		$a_01_2 = {30 78 44 42 61 6e 64 69 74 32 73 } //01 00  0xDBandit2s
		$a_01_3 = {41 73 79 6e 63 54 61 73 6b 4d 65 74 68 6f 64 42 75 69 6c 64 65 72 } //01 00  AsyncTaskMethodBuilder
		$a_01_4 = {3c 52 75 73 73 69 61 56 73 55 6b 72 61 69 6e 65 3e 64 5f 5f } //01 00  <RussiaVsUkraine>d__
		$a_01_5 = {5f 30 78 44 45 63 74 6f 70 6c 33 73 6d 69 63 } //00 00  _0xDEctopl3smic
	condition:
		any of ($a_*)
 
}