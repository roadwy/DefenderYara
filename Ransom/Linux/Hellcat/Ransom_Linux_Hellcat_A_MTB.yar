
rule Ransom_Linux_Hellcat_A_MTB{
	meta:
		description = "Ransom:Linux/Hellcat.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,08 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {6b 69 6c 6c 5f 61 6c 6c 5f 76 6d 73 } //2 kill_all_vms
		$a_01_1 = {6b 69 6c 6c 5f 76 6d 73 } //2 kill_vms
		$a_01_2 = {65 73 78 63 6c 69 20 76 6d 20 70 72 6f 63 65 73 73 20 6b 69 6c 6c 20 2d 2d 74 79 70 65 3d } //2 esxcli vm process kill --type=
		$a_01_3 = {52 65 61 64 6d 65 2e 25 73 2e 74 78 74 } //1 Readme.%s.txt
		$a_01_4 = {62 5f 73 6b 69 70 5f 73 6f 6d 65 5f 66 69 6c 65 } //1 b_skip_some_file
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}