
rule Trojan_Win32_Zbot_SMT_MTB{
	meta:
		description = "Trojan:Win32/Zbot.SMT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 "
		
	strings :
		$a_01_0 = {50 8b ec 8b 4d 10 33 d2 8b 75 04 8b 36 03 f3 33 c0 50 c1 c8 07 31 04 24 ac 84 c0 75 f5 58 } //10
		$a_01_1 = {2e 6f 62 63 68 71 62 } //1 .obchqb
		$a_80_2 = {6f 61 39 52 4c 56 50 35 4a } //oa9RLVP5J  1
		$a_80_3 = {6f 41 4b 57 45 4d 59 45 } //oAKWEMYE  1
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=13
 
}