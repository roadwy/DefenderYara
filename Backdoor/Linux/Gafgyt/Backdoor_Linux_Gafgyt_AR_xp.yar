
rule Backdoor_Linux_Gafgyt_AR_xp{
	meta:
		description = "Backdoor:Linux/Gafgyt.AR!xp,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {4b 2a 5e 49 2a 5e 4c 2a 5e 4c 2a 5e 41 2a 5e 54 2a 5e 54 2a 5e 4b } //1 K*^I*^L*^L*^A*^T*^T*^K
		$a_00_1 = {4c 2a 5e 4f 2a 5e 4c 2a 5e 4e 2a 5e 4f 2a 5e 47 2a 5e 54 2a 5e 46 2a 5e 4f } //1 L*^O*^L*^N*^O*^G*^T*^F*^O
		$a_00_2 = {4a 2a 5e 55 2a 5e 4e 2a 5e 4b } //1 J*^U*^N*^K
		$a_00_3 = {55 2a 5e 44 2a 5e 50 } //1 U*^D*^P
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}