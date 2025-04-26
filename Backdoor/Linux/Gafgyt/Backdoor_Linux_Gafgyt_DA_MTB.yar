
rule Backdoor_Linux_Gafgyt_DA_MTB{
	meta:
		description = "Backdoor:Linux/Gafgyt.DA!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {42 65 61 6e 73 20 4e 69 67 67 61 20 42 6f 74 } //1 Beans Nigga Bot
		$a_01_1 = {62 6f 74 6b 69 6c 6c } //1 botkill
		$a_01_2 = {73 6b 69 64 6c 6f 72 64 } //1 skidlord
		$a_01_3 = {50 4f 4e 47 } //1 PONG
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}