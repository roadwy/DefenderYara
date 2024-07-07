
rule Trojan_Win64_IcedID_F_MTB{
	meta:
		description = "Trojan:Win64/IcedID.F!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 83 c0 02 48 89 44 24 40 e9 30 04 00 00 8a 40 01 88 44 24 21 66 3b d2 74 1a 48 03 c8 48 8b c1 66 3b ed 74 e9 } //3
	condition:
		((#a_01_0  & 1)*3) >=3
 
}
rule Trojan_Win64_IcedID_F_MTB_2{
	meta:
		description = "Trojan:Win64/IcedID.F!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {79 61 73 66 75 68 6b 61 73 66 69 61 6a 73 6b 66 } //1 yasfuhkasfiajskf
		$a_01_1 = {67 6c 79 70 68 2d 61 72 72 6f 77 2d 68 74 6d 6c } //1 glyph-arrow-html
		$a_01_2 = {2e 73 68 74 6c 6c } //1 .shtll
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule Trojan_Win64_IcedID_F_MTB_3{
	meta:
		description = "Trojan:Win64/IcedID.F!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 8b 44 24 38 48 8b 4c 24 40 e9 57 01 00 00 8a 00 88 44 24 20 eb e9 48 8b 44 24 38 48 8b 4c 24 40 66 3b db 74 00 48 03 c8 48 8b c1 3a db 74 df } //3
	condition:
		((#a_01_0  & 1)*3) >=3
 
}
rule Trojan_Win64_IcedID_F_MTB_4{
	meta:
		description = "Trojan:Win64/IcedID.F!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {8a 40 01 88 44 24 21 3a ff 74 } //1
		$a_03_1 = {48 03 c8 48 8b c1 66 3b 90 01 01 74 90 00 } //1
		$a_03_2 = {48 8b 44 24 40 48 8b 4c 24 48 66 3b 90 01 01 74 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}