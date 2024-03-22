
rule Trojan_BAT_LummaStealer_CCHE_MTB{
	meta:
		description = "Trojan:BAT/LummaStealer.CCHE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 03 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 00 32 00 31 00 32 00 32 00 30 00 32 00 31 00 32 00 61 00 32 00 32 00 31 00 32 00 30 00 32 00 31 00 32 00 6c 00 32 00 31 00 32 00 30 00 32 00 31 00 32 00 6c 00 32 00 31 00 32 00 30 00 32 00 31 00 32 00 42 00 32 00 31 00 32 00 30 00 32 00 31 00 32 00 79 00 32 00 31 00 32 00 31 00 32 00 32 00 30 00 32 00 31 00 32 00 4e 00 32 00 31 00 32 00 30 00 32 00 31 00 32 00 61 00 32 00 31 00 32 00 30 00 32 00 32 00 31 00 32 00 31 00 32 00 6d 00 } //01 00  C21220212a22120212l2120212l2120212B2120212y2121220212N2120212a2120221212m
		$a_01_1 = {53 00 60 00 74 00 60 00 75 00 60 00 62 00 60 00 63 00 60 00 72 00 60 00 79 00 60 00 2e 00 60 00 4e 00 60 00 49 00 60 00 4b 00 60 00 42 00 60 00 49 00 60 00 4e 00 60 00 41 00 60 00 52 00 60 00 59 00 60 00 33 00 60 00 32 00 60 00 62 00 60 00 69 00 60 00 74 00 } //01 00  S`t`u`b`c`r`y`.`N`I`K`B`I`N`A`R`Y`3`2`b`i`t
		$a_01_2 = {42 00 32 00 31 00 32 00 30 00 32 00 31 00 32 00 79 00 32 00 31 00 32 00 31 00 32 00 32 00 30 00 32 00 31 00 32 00 4e 00 32 00 31 00 32 00 30 00 32 00 31 00 32 00 61 00 32 00 31 00 32 00 30 00 32 00 32 00 31 00 32 00 31 00 32 00 6d 00 32 00 32 00 31 00 32 00 30 00 32 00 31 00 32 00 65 00 } //01 00  B2120212y2121220212N2120212a2120221212m22120212e
		$a_01_3 = {4c 00 33 00 32 00 33 00 31 00 33 00 32 00 33 00 33 00 6f 00 33 00 32 00 33 00 31 00 33 00 32 00 33 00 41 00 33 00 32 00 33 00 31 00 33 00 32 00 33 00 64 00 } //01 00  L32313233o3231323A3231323d
		$a_01_4 = {65 00 37 00 38 00 37 00 39 00 37 00 38 00 37 00 74 00 37 00 38 00 37 00 39 00 37 00 38 00 37 00 54 00 37 00 38 00 37 00 39 00 37 00 38 00 37 00 79 00 37 00 38 00 37 00 39 00 37 00 38 00 37 00 70 00 } //00 00  e7879787t7879787T7879787y7879787p
	condition:
		any of ($a_*)
 
}