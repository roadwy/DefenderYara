
rule Trojan_BAT_AsyncRAT_RDK_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.RDK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {38 64 62 62 37 30 38 62 2d 61 38 38 63 2d 34 36 31 30 2d 39 63 66 36 2d 37 33 32 39 36 63 64 61 33 62 64 34 } //02 00 
		$a_01_1 = {11 06 11 06 06 94 11 06 08 94 58 20 00 01 00 00 5d 94 0d 11 07 07 04 07 91 09 61 d2 9c 00 07 17 58 0b } //00 00 
	condition:
		any of ($a_*)
 
}