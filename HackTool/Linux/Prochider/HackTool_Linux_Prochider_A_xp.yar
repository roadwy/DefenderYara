
rule HackTool_Linux_Prochider_A_xp{
	meta:
		description = "HackTool:Linux/Prochider.A!xp,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {50 72 6f 63 65 73 73 20 53 74 61 63 6b 20 46 61 6b 65 72 } //1 Process Stack Faker
		$a_01_1 = {55 73 61 67 65 3a 20 25 73 20 5b 6f 70 74 69 6f 6e 73 5d 20 63 6f 6d 6d 61 6e 64 20 61 72 67 31 20 61 72 67 32 } //1 Usage: %s [options] command arg1 arg2
		$a_01_2 = {72 65 6e 69 63 65 20 70 72 6f 63 65 73 73 } //1 renice process
		$a_01_3 = {66 61 6b 65 20 70 72 6f 63 65 73 73 20 6e 61 6d 65 } //1 fake process name
		$a_01_4 = {73 70 61 77 6e 65 64 20 70 72 6f 63 65 73 73 } //1 spawned process
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}