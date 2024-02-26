
rule Trojan_BAT_Nanocore_ABL_MTB{
	meta:
		description = "Trojan:BAT/Nanocore.ABL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {57 5d a2 df 09 1f 00 00 00 fa 25 33 00 16 00 00 02 00 00 00 c5 00 00 00 1f 00 00 00 86 01 00 00 76 02 00 00 e0 01 00 00 } //01 00 
		$a_01_1 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_01_2 = {50 6f 4b 65 4d 61 70 56 36 } //01 00  PoKeMapV6
		$a_01_3 = {24 66 33 34 36 65 35 35 66 2d 34 36 64 33 2d 34 33 61 38 2d 39 31 65 39 2d 35 30 66 38 37 65 30 63 64 35 63 62 } //01 00  $f346e55f-46d3-43a8-91e9-50f87e0cd5cb
		$a_01_4 = {50 00 6f 00 4b 00 65 00 4d 00 61 00 70 00 56 00 36 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //00 00  PoKeMapV6.Resources
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_Nanocore_ABL_MTB_2{
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