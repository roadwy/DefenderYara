
rule Trojan_Win64_Ulise_MA_MTB{
	meta:
		description = "Trojan:Win64/Ulise.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 03 00 00 05 00 "
		
	strings :
		$a_01_0 = {80 64 37 f8 f7 67 8d 4f 06 48 89 4e f8 31 c0 88 05 f7 2c 17 00 48 89 1e 48 89 46 18 c7 46 20 01 00 00 00 48 89 73 28 48 8d 46 30 0f b7 4b 02 48 8d 14 01 48 89 53 18 48 01 f7 48 29 cf } //02 00 
		$a_01_1 = {67 72 65 61 74 35 } //01 00 
		$a_01_2 = {44 6c 6c 49 6e 73 74 61 6c 6c } //00 00 
	condition:
		any of ($a_*)
 
}