
rule Trojan_Win32_Sofacy_B_dha{
	meta:
		description = "Trojan:Win32/Sofacy.B!dha,SIGNATURE_TYPE_PEHSTR,14 00 14 00 03 00 00 0a 00 "
		
	strings :
		$a_01_0 = {83 7d fc 00 b0 20 6a 40 0f b6 c0 59 0f 45 c1 8b e5 } //0a 00 
		$a_01_1 = {32 40 7b 67 47 2c 3f 42 22 6b } //0a 00  2@{gG,?B"k
		$a_01_2 = {79 25 09 09 22 40 0c 70 0c 0f 5e 2c } //00 00  ╹उ䀢瀌༌ⱞ
		$a_01_3 = {00 5d 04 00 00 } //dc b1 
	condition:
		any of ($a_*)
 
}