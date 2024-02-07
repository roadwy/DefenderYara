
rule Backdoor_Linux_Gafgyt_AO_MTB{
	meta:
		description = "Backdoor:Linux/Gafgyt.AO!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {2f 62 69 6e 2f 62 75 73 79 62 6f 78 20 42 4f 54 4e 45 54 } //01 00  /bin/busybox BOTNET
		$a_00_1 = {68 61 63 6b 74 68 65 77 6f 72 6c 64 31 33 33 37 } //01 00  hacktheworld1337
		$a_00_2 = {6d 6f 62 69 72 6f 6f 74 } //01 00  mobiroot
		$a_00_3 = {74 73 75 6e 61 6d 69 } //01 00  tsunami
		$a_00_4 = {68 75 6e 74 35 37 35 39 } //00 00  hunt5759
	condition:
		any of ($a_*)
 
}