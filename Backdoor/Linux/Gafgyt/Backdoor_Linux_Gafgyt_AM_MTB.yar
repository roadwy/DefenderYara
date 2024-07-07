
rule Backdoor_Linux_Gafgyt_AM_MTB{
	meta:
		description = "Backdoor:Linux/Gafgyt.AM!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {62 6f 74 6b 69 6c 6c } //1 botkill
		$a_00_1 = {74 65 6c 6e 65 74 61 64 6d 69 6e } //1 telnetadmin
		$a_00_2 = {42 4f 54 4e 45 54 } //1 BOTNET
		$a_00_3 = {68 75 6e 74 35 37 35 39 } //1 hunt5759
		$a_00_4 = {37 75 6a 4d 6b 6f 30 61 64 6d 69 6e } //1 7ujMko0admin
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}