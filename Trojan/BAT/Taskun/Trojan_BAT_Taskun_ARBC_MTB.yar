
rule Trojan_BAT_Taskun_ARBC_MTB{
	meta:
		description = "Trojan:BAT/Taskun.ARBC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {00 08 11 04 08 8e 69 5d 08 11 04 08 8e 69 5d 91 09 11 04 1f 16 5d 6f 90 01 03 0a 61 08 11 04 17 58 08 8e 69 5d 91 20 00 01 00 00 58 20 00 01 00 00 5d 59 d2 9c 11 04 15 58 13 04 00 11 04 16 fe 04 16 fe 01 13 07 11 07 2d b6 90 00 } //02 00 
		$a_80_1 = {51 4c 43 48 41 70 70 6c 65 5f 42 55 53 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //QLCHApple_BUS.Properties.Resources  00 00 
	condition:
		any of ($a_*)
 
}