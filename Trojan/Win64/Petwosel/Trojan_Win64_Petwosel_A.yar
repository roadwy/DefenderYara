
rule Trojan_Win64_Petwosel_A{
	meta:
		description = "Trojan:Win64/Petwosel.A,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 04 00 00 "
		
	strings :
		$a_01_0 = {f1 d5 00 fa 4c 62 cc f4 0f 0b } //10
		$a_03_1 = {4d 5a 45 52 e8 00 00 00 00 59 48 83 e9 09 48 8b c1 48 05 ?? ?? ?? ?? ff d0 c3 } //1
		$a_03_2 = {4d 5a 45 52 e8 00 00 00 00 5b 48 83 eb 09 53 48 81 c3 ?? ?? ?? ?? ff d0 c3 } //1
		$a_03_3 = {4d 5a 45 52 e8 00 00 00 00 58 83 e8 09 50 05 ?? ?? ?? ?? ff d0 c3 } //1
	condition:
		((#a_01_0  & 1)*10+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=11
 
}