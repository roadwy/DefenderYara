
rule Trojan_AndroidOS_SmForw_A_MTB{
	meta:
		description = "Trojan:AndroidOS/SmForw.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {51 30 34 39 55 30 68 42 57 55 5a 4e } //01 00  Q049U0hBWUZN
		$a_00_1 = {71 71 3a 31 32 37 39 35 32 35 37 33 38 } //01 00  qq:1279525738
		$a_00_2 = {42 41 48 2e 6a 61 76 61 } //01 00  BAH.java
		$a_00_3 = {39 39 39 39 2d 30 31 2d 31 35 20 30 30 3a 35 30 3a 30 30 } //00 00  9999-01-15 00:50:00
	condition:
		any of ($a_*)
 
}