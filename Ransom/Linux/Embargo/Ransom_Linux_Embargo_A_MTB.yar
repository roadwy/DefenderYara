
rule Ransom_Linux_Embargo_A_MTB{
	meta:
		description = "Ransom:Linux/Embargo.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {65 6d 62 61 72 67 6f 3a 3a 63 72 79 70 74 65 72 } //1 embargo::crypter
		$a_01_1 = {76 69 6d 2d 63 6d 64 20 76 6d 73 76 63 2f 67 65 74 61 6c 6c 76 6d 73 } //1 vim-cmd vmsvc/getallvms
		$a_01_2 = {66 75 6c 6c 5f 65 6e 63 72 79 70 74 5f 65 78 74 } //1 full_encrypt_ext
		$a_01_3 = {78 61 72 67 73 20 2d 6e 31 20 76 69 6d 2d 63 6d 64 20 76 6d 73 76 63 2f 73 6e 61 70 73 68 6f 74 2e 72 65 6d 6f 76 65 61 6c 6c } //1 xargs -n1 vim-cmd vmsvc/snapshot.removeall
		$a_01_4 = {65 73 78 63 6c 69 20 76 6d 20 70 72 6f 63 65 73 73 20 6b 69 6c 6c 20 2d 2d 74 79 70 65 3d 66 6f 72 63 65 20 2d 2d 77 6f 72 6c 64 2d 69 64 3d } //1 esxcli vm process kill --type=force --world-id=
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}