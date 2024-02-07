
rule Trojan_Win64_Bumblebee_MKO_MTB{
	meta:
		description = "Trojan:Win64/Bumblebee.MKO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {41 d3 c8 49 63 81 90 01 04 41 ba 90 01 04 44 01 04 82 45 8b c2 49 8b 81 90 01 04 8b 88 90 01 04 81 c1 90 01 04 41 3b ca 76 33 4d 8d 91 90 01 04 49 8b 81 90 01 04 41 ff c0 4c 31 90 01 05 49 8b 81 90 01 04 8b 90 01 05 81 c2 90 01 04 49 63 c0 48 3b c2 72 90 00 } //01 00 
		$a_01_1 = {4c 4f 47 31 37 66 76 } //01 00  LOG17fv
		$a_01_2 = {59 63 57 72 34 71 49 38 } //00 00  YcWr4qI8
	condition:
		any of ($a_*)
 
}