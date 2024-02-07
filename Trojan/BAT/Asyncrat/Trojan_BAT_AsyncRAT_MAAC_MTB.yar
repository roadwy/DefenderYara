
rule Trojan_BAT_AsyncRAT_MAAC_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.MAAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 0a 00 "
		
	strings :
		$a_03_0 = {0a 0b 07 28 90 01 01 00 00 0a 03 6f 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 0c 06 08 6f 90 01 01 00 00 0a 06 18 6f 12 00 00 0a 06 6f 13 00 00 0a 02 16 02 8e 69 90 00 } //01 00 
		$a_01_1 = {4c 00 6e 00 76 00 62 00 6b 00 65 00 } //01 00  Lnvbke
		$a_01_2 = {64 00 61 00 6f 00 4c 00 } //01 00  daoL
		$a_01_3 = {66 00 37 00 78 00 70 00 } //00 00  f7xp
	condition:
		any of ($a_*)
 
}