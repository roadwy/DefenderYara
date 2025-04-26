
rule Backdoor_Linux_Gafgyt_D_MTB{
	meta:
		description = "Backdoor:Linux/Gafgyt.D!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {31 38 35 2e 31 33 32 2e 35 33 2e 32 33 38 2f 69 6e 66 65 63 74 } //1 185.132.53.238/infect
		$a_00_1 = {2f 74 6d 70 2f 6a 65 53 6a 61 78 } //1 /tmp/jeSjax
		$a_00_2 = {6e 63 6f 72 72 65 63 74 } //1 ncorrect
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}