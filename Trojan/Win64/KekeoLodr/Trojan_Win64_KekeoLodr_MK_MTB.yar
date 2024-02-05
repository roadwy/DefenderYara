
rule Trojan_Win64_KekeoLodr_MK_MTB{
	meta:
		description = "Trojan:Win64/KekeoLodr.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {48 89 f0 44 89 f1 48 83 c7 90 01 01 48 d3 f8 41 30 44 1c 90 01 01 49 39 fd 75 90 01 01 48 ff c6 48 83 c3 90 01 01 71 90 00 } //01 00 
		$a_03_1 = {48 ff c3 42 88 54 37 10 83 e3 0f 49 ff c6 e9 90 0a 22 00 48 8d 0d 90 01 04 42 8a 54 35 90 01 01 32 94 19 90 00 } //00 00 
		$a_00_2 = {5d } //04 00 
	condition:
		any of ($a_*)
 
}