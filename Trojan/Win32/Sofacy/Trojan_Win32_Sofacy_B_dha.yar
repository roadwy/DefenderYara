
rule Trojan_Win32_Sofacy_B_dha{
	meta:
		description = "Trojan:Win32/Sofacy.B!dha,SIGNATURE_TYPE_PEHSTR,14 00 14 00 03 00 00 "
		
	strings :
		$a_01_0 = {83 7d fc 00 b0 20 6a 40 0f b6 c0 59 0f 45 c1 8b e5 } //10
		$a_01_1 = {32 40 7b 67 47 2c 3f 42 22 6b } //10 2@{gG,?B"k
		$a_01_2 = {79 25 09 09 22 40 0c 70 0c 0f 5e 2c } //10 ╹उ䀢瀌༌ⱞ
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10) >=20
 
}