
rule Trojan_AndroidOS_SmForw_A_MTB{
	meta:
		description = "Trojan:AndroidOS/SmForw.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {51 30 34 39 55 30 68 42 57 55 5a 4e } //1 Q049U0hBWUZN
		$a_00_1 = {71 71 3a 31 32 37 39 35 32 35 37 33 38 } //1 qq:1279525738
		$a_00_2 = {42 41 48 2e 6a 61 76 61 } //1 BAH.java
		$a_00_3 = {39 39 39 39 2d 30 31 2d 31 35 20 30 30 3a 35 30 3a 30 30 } //1 9999-01-15 00:50:00
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}