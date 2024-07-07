
rule Backdoor_BAT_NetwireRAT_A_MTB{
	meta:
		description = "Backdoor:BAT/NetwireRAT.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 06 00 00 "
		
	strings :
		$a_03_0 = {20 00 01 00 00 14 14 17 8d 90 01 01 00 00 01 25 16 02 a2 28 90 00 } //2
		$a_01_1 = {07 08 09 28 } //2 ࠇ⠉
		$a_01_2 = {00 06 d2 06 28 } //2
		$a_01_3 = {59 1c 58 0d } //2 ᱙൘
		$a_01_4 = {06 17 58 0a } //2
		$a_01_5 = {08 1a 59 1b 58 0c } //2 ᨈ᭙ౘ
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2) >=12
 
}