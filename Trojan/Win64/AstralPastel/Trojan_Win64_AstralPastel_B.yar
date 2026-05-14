
rule Trojan_Win64_AstralPastel_B{
	meta:
		description = "Trojan:Win64/AstralPastel.B,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {44 65 6c 65 74 65 20 46 61 69 6c 65 64 21 } //1 Delete Failed!
		$a_01_1 = {25 73 25 73 25 25 61 25 64 } //1 %s%s%%a%d
		$a_01_2 = {25 73 09 25 73 09 25 73 } //1 猥┉ॳ猥
		$a_01_3 = {25 73 21 25 73 } //1 %s!%s
		$a_01_4 = {65 72 72 6f 72 31 2c 63 6f 64 65 3a 20 25 64 } //1 error1,code: %d
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}