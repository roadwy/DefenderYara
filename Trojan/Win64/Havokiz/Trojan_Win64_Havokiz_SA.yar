
rule Trojan_Win64_Havokiz_SA{
	meta:
		description = "Trojan:Win64/Havokiz.SA,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 09 00 00 "
		
	strings :
		$a_01_0 = {17 bd a0 1a 3a ac d0 58 } //10
		$a_01_1 = {33 cf 48 d7 a3 ed ba 42 } //10
		$a_01_2 = {5b 59 19 59 d9 ed ed 72 } //10
		$a_01_3 = {9b 7f 0f 22 8a 5c a2 9e } //10
		$a_01_4 = {55 08 5b 69 d3 dc 65 c8 } //10
		$a_01_5 = {86 c7 3f 8a 17 f4 69 a5 } //10
		$a_01_6 = {08 d7 ae 94 1f 6e 0a 6e } //10
		$a_01_7 = {ce ce 14 8f d9 ff 2c 66 } //10
		$a_01_8 = {04 84 19 23 bf ff 2c 66 } //10
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*10+(#a_01_5  & 1)*10+(#a_01_6  & 1)*10+(#a_01_7  & 1)*10+(#a_01_8  & 1)*10) >=10
 
}