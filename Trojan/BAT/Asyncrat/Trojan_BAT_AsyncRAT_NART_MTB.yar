
rule Trojan_BAT_AsyncRAT_NART_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.NART!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 05 00 "
		
	strings :
		$a_03_0 = {72 0d 00 00 70 28 90 01 01 00 00 06 0a dd 90 01 01 00 00 00 26 dd 90 01 01 00 00 00 06 2c e6 06 73 90 01 01 00 00 0a 0b 73 90 01 01 00 00 0a 0c 07 16 73 90 01 01 00 00 0a 73 90 01 01 00 00 0a 0d 09 08 6f 90 01 01 00 00 0a dd 90 01 01 00 00 00 09 39 90 01 01 00 00 00 90 00 } //01 00 
		$a_01_1 = {57 69 6e 64 6f 77 73 46 6f 72 6d 73 41 70 70 38 38 } //01 00 
		$a_01_2 = {4f 79 62 69 69 } //00 00 
	condition:
		any of ($a_*)
 
}