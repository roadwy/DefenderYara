
rule Trojan_BAT_Bladabindi_NEK_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.NEK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {31 34 33 61 39 32 30 32 2d 61 66 35 63 2d 34 64 39 33 2d 38 32 66 39 2d 36 61 63 33 34 34 63 34 35 38 32 61 } //01 00  143a9202-af5c-4d93-82f9-6ac344c4582a
		$a_01_1 = {53 46 55 34 6d 62 54 33 47 4d 72 65 74 37 54 48 6f 6e 66 } //01 00  SFU4mbT3GMret7THonf
		$a_01_2 = {66 69 65 6c 64 69 6d 70 6c 33 } //01 00  fieldimpl3
		$a_01_3 = {62 37 37 61 35 63 35 36 31 39 33 34 65 30 38 39 } //01 00  b77a5c561934e089
		$a_01_4 = {24 24 6d 65 74 68 6f 64 30 78 36 30 30 30 30 31 32 2d 31 } //00 00  $$method0x6000012-1
	condition:
		any of ($a_*)
 
}