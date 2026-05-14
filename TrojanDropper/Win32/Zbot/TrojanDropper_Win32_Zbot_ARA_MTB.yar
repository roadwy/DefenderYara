
rule TrojanDropper_Win32_Zbot_ARA_MTB{
	meta:
		description = "TrojanDropper:Win32/Zbot.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {86 88 14 08 40 3b c7 72 f2 } //2
		$a_01_1 = {86 88 0c 30 40 3b c7 72 f2 } //2
		$a_01_2 = {80 f3 19 88 1c 32 42 3b d1 72 ef } //3
		$a_01_3 = {80 34 18 19 40 3b c1 72 f7 } //3
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*3+(#a_01_3  & 1)*3) >=5
 
}