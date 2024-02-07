
rule Trojan_BAT_NjRat_NN_MTB{
	meta:
		description = "Trojan:BAT/NjRat.NN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {06 6f d1 00 00 06 13 06 06 6f 90 01 01 00 00 06 13 07 11 06 8d 90 01 01 00 00 01 13 08 06 11 08 16 11 08 8e 69 6f 90 01 01 00 00 0a 26 11 08 73 90 01 01 00 00 06 07 11 05 11 07 6f 90 01 01 00 00 06 26 11 05 11 07 58 13 05 11 05 11 04 32 ba 90 00 } //01 00 
		$a_01_1 = {64 6a 6b 64 6b 64 6b } //00 00  djkdkdk
	condition:
		any of ($a_*)
 
}