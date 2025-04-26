
rule Backdoor_Linux_Gafgyt_BW_xp{
	meta:
		description = "Backdoor:Linux/Gafgyt.BW!xp,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {53 61 72 75 67 61 6d 69 } //1 Sarugami
		$a_01_1 = {62 6f 74 6b 69 6c 6c } //1 botkill
		$a_01_2 = {75 64 70 00 2f 64 65 76 2f 6e 75 6c 6c } //1
		$a_01_3 = {50 4f 4e 47 } //1 PONG
		$a_01_4 = {50 49 4e 47 } //1 PING
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}