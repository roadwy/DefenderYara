
rule Backdoor_Linux_Gummo_A_xp{
	meta:
		description = "Backdoor:Linux/Gummo.A!xp,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {67 75 6d 6d 6f 20 62 61 63 6b 64 6f 6f 72 } //2 gummo backdoor
		$a_01_1 = {57 65 6c 63 6f 6d 65 20 54 6f 20 47 75 6d 6d 6f 20 42 61 63 6b 64 6f 6f 72 20 53 65 72 76 65 72 } //2 Welcome To Gummo Backdoor Server
		$a_01_2 = {72 65 77 74 } //1 rewt
		$a_01_3 = {77 69 70 65 6f 75 74 } //1 wipeout
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}