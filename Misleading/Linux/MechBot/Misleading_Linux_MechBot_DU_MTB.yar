
rule Misleading_Linux_MechBot_DU_MTB{
	meta:
		description = "Misleading:Linux/MechBot.DU!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 06 00 00 "
		
	strings :
		$a_01_0 = {41 63 79 63 6d 65 63 68 20 42 6f 74 20 25 64 20 43 6f 6e 66 69 67 } //1 Acycmech Bot %d Config
		$a_01_1 = {41 63 79 63 6d 65 63 68 20 74 72 69 67 67 65 72 64 20 62 79 20 61 64 6d 69 6e 20 28 68 65 6c 6c 6f 20 5a 65 74 6f 6f 29 } //1 Acycmech triggerd by admin (hello Zetoo)
		$a_01_2 = {72 6d 20 2d 72 66 20 2e 2e 2f 6d 65 63 68 2e 73 65 74 3b 63 70 20 73 65 72 76 65 72 2e 74 78 74 20 2e 2e 2f 6d 65 63 68 2e 73 65 74 } //1 rm -rf ../mech.set;cp server.txt ../mech.set
		$a_01_3 = {21 74 65 6c 6e 65 74 40 65 6e 65 72 67 79 6d 65 63 68 } //1 !telnet@energymech
		$a_01_4 = {4b 69 6c 6c 69 6e 67 20 6d 65 63 68 3a 20 25 73 } //1 Killing mech: %s
		$a_01_5 = {41 64 64 65 64 20 74 6f 20 6d 65 63 68 20 63 6f 72 65 } //1 Added to mech core
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=3
 
}