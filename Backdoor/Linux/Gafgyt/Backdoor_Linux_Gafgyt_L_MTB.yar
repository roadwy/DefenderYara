
rule Backdoor_Linux_Gafgyt_L_MTB{
	meta:
		description = "Backdoor:Linux/Gafgyt.L!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {6b 69 6c 6c 64 65 76 69 63 65 73 } //1 killdevices
		$a_01_1 = {73 74 64 70 6c 61 69 6e } //1 stdplain
		$a_01_2 = {4d 6f 64 69 66 69 65 64 20 42 6f 74 } //1 Modified Bot
		$a_01_3 = {42 79 70 61 73 73 } //1 Bypass
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}