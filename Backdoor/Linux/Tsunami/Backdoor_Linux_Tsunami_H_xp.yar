
rule Backdoor_Linux_Tsunami_H_xp{
	meta:
		description = "Backdoor:Linux/Tsunami.H!xp,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {73 70 6f 6f 66 73 6d } //2 spoofsm
		$a_01_1 = {67 65 74 73 70 6f 6f 66 73 } //1 getspoofs
		$a_01_2 = {6b 69 6c 6c 61 6c 6c } //1 killall
		$a_01_3 = {74 73 75 6e 61 6d 69 } //1 tsunami
		$a_01_4 = {6b 61 69 74 65 6e 2e 63 } //1 kaiten.c
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}