
rule Trojan_BAT_Tedy_PSKD_MTB{
	meta:
		description = "Trojan:BAT/Tedy.PSKD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {28 df 00 00 0a 1a 3b 0a 00 00 00 7e ae 00 00 04 38 05 00 00 00 7e ad 00 00 04 0b 7e e2 00 00 0a 07 8e 69 73 f7 00 00 0a 20 00 30 00 00 1f 40 28 80 01 00 06 0a 07 16 06 07 8e 69 28 f8 00 00 0a 06 d0 2d 00 00 02 28 63 00 00 0a 28 f9 00 00 0a 74 2d 00 00 02 0c 12 03 fe 15 94 00 00 01 1a 8d 7b 00 00 01 13 04 11 04 19 28 fa 00 00 0a 0d 08 02 11 04 6f 9b 01 00 06 dd 1d 00 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}