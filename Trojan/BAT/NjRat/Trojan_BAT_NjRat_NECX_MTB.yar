
rule Trojan_BAT_NjRat_NECX_MTB{
	meta:
		description = "Trojan:BAT/NjRat.NECX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 04 00 00 0a 00 "
		
	strings :
		$a_03_0 = {02 11 05 17 9a 28 90 01 01 00 00 06 28 90 01 01 00 00 0a 28 90 01 01 00 00 0a 28 90 01 01 00 00 0a 90 00 } //02 00 
		$a_01_1 = {57 4f 4c 46 44 45 43 52 59 50 54 } //02 00  WOLFDECRYPT
		$a_01_2 = {4e 6f 49 73 47 6f 6f 64 } //02 00  NoIsGood
		$a_01_3 = {46 75 63 6b 59 6f 75 } //00 00  FuckYou
	condition:
		any of ($a_*)
 
}