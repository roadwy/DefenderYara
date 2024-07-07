
rule Ransom_Linux_BlackCat_B_MTB{
	meta:
		description = "Ransom:Linux/BlackCat.B!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {65 73 78 63 6c 69 20 2d 2d 66 6f 72 6d 61 74 74 65 72 3d 63 73 76 20 2d 2d 66 6f 72 6d 61 74 2d 70 61 72 61 6d 3d 66 69 65 6c 64 73 3d 3d } //1 esxcli --formatter=csv --format-param=fields==
		$a_01_1 = {65 73 78 63 6c 69 20 76 6d 20 70 72 6f 63 65 73 73 20 6b 69 6c 6c 20 2d 2d 74 79 70 65 3d 66 6f 72 63 65 20 2d 2d 77 6f 72 6c 64 2d 69 64 3d } //1 esxcli vm process kill --type=force --world-id=
		$a_01_2 = {6c 6f 63 6b 65 72 3a 3a 63 6f 72 65 3a 3a 6f 73 3a 3a 6c 69 6e 75 78 3a 3a 63 6f 6d 6d 61 6e 64 } //1 locker::core::os::linux::command
		$a_01_3 = {6c 6f 63 6b 65 72 3a 3a 63 6f 72 65 3a 3a 6f 73 3a 3a 6c 69 6e 75 78 3a 3a 65 73 78 69 } //1 locker::core::os::linux::esxi
		$a_01_4 = {6c 6f 63 6b 65 72 3a 3a 63 6f 72 65 3a 3a 70 69 70 65 6c 69 6e 65 3a 3a 66 69 6c 65 5f 77 6f 72 6b 65 72 5f 70 6f 6f 6c } //1 locker::core::pipeline::file_worker_pool
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}