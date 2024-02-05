
rule Trojan_BAT_Tiny_NTN_MTB{
	meta:
		description = "Trojan:BAT/Tiny.NTN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {28 3c 00 00 0a 02 6f 90 01 03 0a 13 00 20 90 01 03 00 7e 90 01 03 04 3a 90 01 03 ff 26 20 90 01 03 00 38 90 01 03 ff 73 90 01 03 0a 25 17 6f 90 01 03 0a 25 18 6f 90 01 03 0a 11 00 11 00 1f 10 28 90 01 03 06 6f 90 01 03 0a 13 07 20 90 01 03 00 7e 90 01 03 04 39 90 01 03 ff 90 00 } //01 00 
		$a_01_1 = {43 53 68 61 72 70 53 68 65 6c 6c 63 6f 64 65 4c 6f 61 64 65 72 } //00 00 
	condition:
		any of ($a_*)
 
}