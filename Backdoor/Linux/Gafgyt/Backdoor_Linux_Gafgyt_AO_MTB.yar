
rule Backdoor_Linux_Gafgyt_AO_MTB{
	meta:
		description = "Backdoor:Linux/Gafgyt.AO!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {2f 62 69 6e 2f 62 75 73 79 62 6f 78 20 42 4f 54 4e 45 54 } //1 /bin/busybox BOTNET
		$a_00_1 = {68 61 63 6b 74 68 65 77 6f 72 6c 64 31 33 33 37 } //1 hacktheworld1337
		$a_00_2 = {6d 6f 62 69 72 6f 6f 74 } //1 mobiroot
		$a_00_3 = {74 73 75 6e 61 6d 69 } //1 tsunami
		$a_00_4 = {68 75 6e 74 35 37 35 39 } //1 hunt5759
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}