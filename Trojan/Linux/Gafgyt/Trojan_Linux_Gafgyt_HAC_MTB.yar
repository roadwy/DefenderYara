
rule Trojan_Linux_Gafgyt_HAC_MTB{
	meta:
		description = "Trojan:Linux/Gafgyt.HAC!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,3a 00 3a 00 05 00 00 "
		
	strings :
		$a_01_0 = {2f 70 72 6f 63 2f 25 64 2f 65 78 65 } //9 /proc/%d/exe
		$a_01_1 = {25 78 3a 25 78 3a 25 78 3a 25 78 3a 25 78 3a 25 78 3a 25 64 2e 25 64 2e 25 64 2e 25 64 } //11 %x:%x:%x:%x:%x:%x:%d.%d.%d.%d
		$a_01_2 = {55 73 65 72 2d 41 67 65 6e 74 3a 20 25 73 } //8 User-Agent: %s
		$a_01_3 = {64 61 74 61 3d 72 61 6e 64 6f 6d 5f 64 61 74 61 } //17 data=random_data
		$a_01_4 = {3a 5d 3a 25 78 20 25 36 33 5b } //13 :]:%x %63[
	condition:
		((#a_01_0  & 1)*9+(#a_01_1  & 1)*11+(#a_01_2  & 1)*8+(#a_01_3  & 1)*17+(#a_01_4  & 1)*13) >=58
 
}