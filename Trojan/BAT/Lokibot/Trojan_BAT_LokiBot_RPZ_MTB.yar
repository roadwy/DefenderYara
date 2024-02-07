
rule Trojan_BAT_LokiBot_RPZ_MTB{
	meta:
		description = "Trojan:BAT/LokiBot.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {13 06 11 04 28 91 00 00 0a 11 06 28 91 00 00 0a da 04 d6 1f 1a 5d 13 07 07 11 06 28 91 00 00 0a 11 07 d6 28 92 00 00 0a 28 93 00 00 0a 28 94 00 00 0a 0b 00 2b 10 00 07 11 04 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_LokiBot_RPZ_MTB_2{
	meta:
		description = "Trojan:BAT/LokiBot.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {02 07 02 8e 69 5d 02 07 02 8e 69 5d 91 06 07 1f 16 5d 91 61 28 ab 00 00 0a 02 07 17 58 02 8e 69 5d 91 28 ac 00 00 0a 59 20 00 01 00 00 58 20 00 01 00 00 5d d2 9c 07 15 58 0b 07 16 2f c2 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_LokiBot_RPZ_MTB_3{
	meta:
		description = "Trojan:BAT/LokiBot.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {46 00 46 00 46 00 46 00 30 00 30 00 30 00 30 00 30 00 30 00 34 00 30 00 30 00 30 00 30 00 30 00 30 00 30 00 33 00 30 00 30 00 30 00 30 00 39 00 41 00 35 00 44 00 34 00 } //01 00  FFFF00000040000000300009A5D4
		$a_01_1 = {53 00 79 00 73 00 74 00 65 00 6d 00 2e 00 52 00 65 00 66 00 6c 00 65 00 63 00 74 00 69 00 6f 00 6e 00 2e 00 41 00 73 00 73 00 65 00 6d 00 62 00 6c 00 79 00 } //01 00  System.Reflection.Assembly
		$a_01_2 = {52 65 76 65 72 73 65 } //01 00  Reverse
		$a_01_3 = {54 6f 41 72 72 61 79 } //01 00  ToArray
		$a_01_4 = {47 65 74 54 79 70 65 } //01 00  GetType
		$a_01_5 = {54 6f 42 79 74 65 } //01 00  ToByte
		$a_01_6 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //00 00  InvokeMember
	condition:
		any of ($a_*)
 
}