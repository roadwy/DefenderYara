
rule Trojan_AndroidOS_MobOkDropper_A{
	meta:
		description = "Trojan:AndroidOS/MobOkDropper.A,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {44 65 78 43 6c 61 73 73 4c 6f 61 64 65 72 } //01 00  DexClassLoader
		$a_01_1 = {6f 25 73 2e 64 65 78 } //01 00  o%s.dex
		$a_01_2 = {61 48 52 30 63 44 6f 76 4c 32 4a 69 4c 6e 4a 76 64 33 56 30 5a 53 35 6a 62 32 30 3d } //01 00  aHR0cDovL2JiLnJvd3V0ZS5jb20=
		$a_00_3 = {34 35 2e 37 39 2e 31 39 2e 35 39 } //01 00  45.79.19.59
		$a_01_4 = {4c 33 42 6e 62 53 39 79 64 43 39 73 5a 77 3d 3d } //00 00  L3BnbS9ydC9sZw==
	condition:
		any of ($a_*)
 
}