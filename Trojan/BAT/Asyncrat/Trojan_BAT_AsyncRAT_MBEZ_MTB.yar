
rule Trojan_BAT_AsyncRAT_MBEZ_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.MBEZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {1f 32 1f 32 73 90 01 01 00 00 0a 0a 73 90 01 01 00 00 0a 0b 16 0c 38 90 01 01 00 00 00 16 0d 38 90 01 01 00 00 00 06 08 09 07 17 1f 65 6f 90 01 01 00 00 0a 28 90 01 01 00 00 0a 09 17 58 0d 09 1f 32 32 e6 90 00 } //01 00 
		$a_01_1 = {00 00 11 41 00 67 00 6e 00 6f 00 73 00 74 00 69 00 63 00 00 c0 02 a3 b1 } //00 00 
	condition:
		any of ($a_*)
 
}