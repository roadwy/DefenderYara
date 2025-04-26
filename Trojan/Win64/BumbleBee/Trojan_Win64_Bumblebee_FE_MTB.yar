
rule Trojan_Win64_Bumblebee_FE_MTB{
	meta:
		description = "Trojan:Win64/Bumblebee.FE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_01_0 = {45 89 81 c8 05 00 00 49 8b 81 a8 00 00 00 48 8b 88 a8 02 00 00 48 81 e9 08 0f 00 00 49 63 c0 48 3b c1 } //1
		$a_01_1 = {41 2b c8 41 ff c2 0f b6 14 18 d3 e2 } //1
		$a_01_2 = {49 8b 4a 10 48 8b 41 08 48 31 41 38 49 8b 42 10 48 ff 48 08 } //1
		$a_01_3 = {48 89 90 c0 00 00 00 48 8b 8b a8 00 00 00 48 8b 81 88 02 00 00 48 35 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=2
 
}