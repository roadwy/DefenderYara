
rule Trojan_AndroidOS_SAgnt_X_MTB{
	meta:
		description = "Trojan:AndroidOS/SAgnt.X!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {12 01 6e 10 ?? ?? 09 00 0c 03 21 34 21 a5 23 56 ?? ?? 01 12 01 10 } //1
		$a_01_1 = {48 07 0a 02 48 08 03 00 b7 87 8d 77 4f 07 06 02 d8 00 00 01 d8 07 04 ff 37 70 03 00 01 10 d8 02 02 01 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_AndroidOS_SAgnt_X_MTB_2{
	meta:
		description = "Trojan:AndroidOS/SAgnt.X!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {71 00 17 00 00 00 0c 06 07 64 07 46 1a 07 ?? ?? 12 08 1f 08 24 00 07 39 12 0a 1f 0a 04 00 12 0b 1f 0b 04 00 74 06 18 00 06 00 0e 00 } //1
		$a_01_1 = {71 00 29 00 00 00 0c 04 1a 05 62 00 6e 20 28 00 54 00 0c 04 07 41 22 04 19 00 07 49 07 94 07 95 22 06 1c 00 07 69 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}