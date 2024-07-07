
rule Spammer_WinNT_Nuwar_A_sys{
	meta:
		description = "Spammer:WinNT/Nuwar.A!sys,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {65 78 70 6c 6f 72 65 72 00 00 00 00 7a 6c 63 6c } //1
		$a_01_1 = {50 72 6f 74 65 63 74 00 00 73 70 6f 6f 6c 64 72 } //1 牐瑯捥t猀潰汯牤
		$a_01_2 = {83 c4 0c 33 c0 c6 46 10 00 40 5e eb 02 33 c0 } //1
		$a_01_3 = {c2 04 00 64 a1 00 00 00 00 8b 40 04 66 33 c0 } //1
		$a_01_4 = {66 81 38 4d 5a 74 07 2d 00 10 00 00 eb f2 c3 55 8b ec } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}