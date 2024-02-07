
rule Trojan_BAT_Nanocore_ABL_MTB{
	meta:
		description = "Trojan:BAT/Nanocore.ABL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_01_1 = {47 65 74 4d 61 6e 69 66 65 73 74 52 65 73 6f 75 72 63 65 53 74 72 65 61 6d } //01 00  GetManifestResourceStream
		$a_01_2 = {65 36 44 30 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //01 00  e6D0.Resources.resources
		$a_01_3 = {38 34 39 63 63 63 61 32 64 62 61 61 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //01 00  849ccca2dbaa.Resources.resources
		$a_01_4 = {36 32 34 30 62 30 36 66 39 30 2e 72 65 73 } //01 00  6240b06f90.res
		$a_01_5 = {24 35 64 65 35 34 38 37 37 2d 32 34 61 39 2d 34 33 30 39 2d 39 34 30 65 2d 61 37 30 36 66 33 33 35 33 33 65 38 } //00 00  $5de54877-24a9-4309-940e-a706f33533e8
	condition:
		any of ($a_*)
 
}