
rule Backdoor_Linux_DoubleFoxFive_A_dha{
	meta:
		description = "Backdoor:Linux/DoubleFoxFive.A!dha,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {6d 61 69 6e 2e 28 2a 41 67 65 6e 74 29 2e 53 74 61 72 74 } //1 main.(*Agent).Start
		$a_00_1 = {6d 61 69 6e 2e 28 2a 41 67 65 6e 74 29 2e 63 6f 6e 6e 65 63 74 54 6f 52 65 6d 6f 74 65 } //1 main.(*Agent).connectToRemote
		$a_00_2 = {6d 61 69 6e 2e 28 2a 41 67 65 6e 74 29 2e 73 68 65 6c 6c } //1 main.(*Agent).shell
		$a_00_3 = {6d 61 69 6e 2e 28 2a 41 67 65 6e 74 29 2e 65 78 65 63 75 74 65 } //1 main.(*Agent).execute
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}