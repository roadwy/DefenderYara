
rule Backdoor_Linux_Gafgyt_AU_xp{
	meta:
		description = "Backdoor:Linux/Gafgyt.AU!xp,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_00_0 = {62 2a 5e 6f 2a 5e 74 2a 5e 3a 2a 5e 20 2a 5e 25 2a 5e 73 2a 5e 5c 2a 5e 6e } //1 b*^o*^t*^:*^ *^%*^s*^\*^n
		$a_00_1 = {4c 2a 5e 49 2a 5e 4c 2a 5e 42 2a 5e 49 2a 5e 54 2a 5e 43 2a 5e 48 } //1 L*^I*^L*^B*^I*^T*^C*^H
		$a_00_2 = {55 2a 5e 44 2a 5e 50 } //1 U*^D*^P
		$a_00_3 = {4b 2a 5e 49 2a 5e 4c 2a 5e 4c } //1 K*^I*^L*^L
		$a_00_4 = {4c 2a 5e 55 2a 5e 43 2a 5e 4b 2a 5e 59 2a 5e 4c 2a 5e 49 2a 5e 4c 2a 5e 44 2a 5e 55 2a 5e 44 2a 5e 45 } //1 L*^U*^C*^K*^Y*^L*^I*^L*^D*^U*^D*^E
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=4
 
}