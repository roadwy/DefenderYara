
rule Trojan_Win64_Sirefef_H{
	meta:
		description = "Trojan:Win64/Sirefef.H,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 06 00 00 "
		
	strings :
		$a_01_0 = {48 83 ef 08 ff ce 48 8b 1f 48 83 27 00 48 85 db } //5
		$a_01_1 = {41 81 f8 64 69 73 63 } //1
		$a_01_2 = {41 81 f8 72 65 63 76 } //1
		$a_01_3 = {2d 46 74 65 67 } //1 -Fteg
		$a_01_4 = {81 7d 08 73 77 65 6e } //1
		$a_01_5 = {81 7b 14 4c 74 65 72 } //1
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=8
 
}
rule Trojan_Win64_Sirefef_H_2{
	meta:
		description = "Trojan:Win64/Sirefef.H,SIGNATURE_TYPE_ARHSTR_EXT,08 00 08 00 06 00 00 "
		
	strings :
		$a_01_0 = {48 83 ef 08 ff ce 48 8b 1f 48 83 27 00 48 85 db } //5
		$a_01_1 = {41 81 f8 64 69 73 63 } //1
		$a_01_2 = {41 81 f8 72 65 63 76 } //1
		$a_01_3 = {2d 46 74 65 67 } //1 -Fteg
		$a_01_4 = {81 7d 08 73 77 65 6e } //1
		$a_01_5 = {81 7b 14 4c 74 65 72 } //1
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=8
 
}