
rule Backdoor_Linux_Gafgyt_F_MTB{
	meta:
		description = "Backdoor:Linux/Gafgyt.F!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {68 6f 68 6f 20 62 6f 74 6e 65 74 } //1 hoho botnet
		$a_00_1 = {2e 2f 2e 61 6b 61 6d 65 } //1 ./.akame
		$a_00_2 = {61 6b 61 6d 65 62 6f 74 6e 65 74 } //1 akamebotnet
		$a_00_3 = {73 70 6f 6f 66 65 64 } //1 spoofed
		$a_00_4 = {62 69 6e 73 2f 61 6b 61 6d 65 2e } //1 bins/akame.
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}