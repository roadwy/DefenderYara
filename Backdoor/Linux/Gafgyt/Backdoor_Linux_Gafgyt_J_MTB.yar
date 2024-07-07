
rule Backdoor_Linux_Gafgyt_J_MTB{
	meta:
		description = "Backdoor:Linux/Gafgyt.J!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {48 54 54 50 53 54 4f 4d 50 } //1 HTTPSTOMP
		$a_01_1 = {4f 56 48 4b 49 4c 4c } //1 OVHKILL
		$a_01_2 = {43 46 42 59 50 41 53 53 } //1 CFBYPASS
		$a_01_3 = {4e 46 4f 4b 49 4c 4c } //1 NFOKILL
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}