
rule Ransom_Linux_Babuk_T_MTB{
	meta:
		description = "Ransom:Linux/Babuk.T!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {65 6e 73 75 72 65 41 6c 6c 56 4d 73 53 68 75 74 64 6f 77 6e } //1 ensureAllVMsShutdown
		$a_01_1 = {65 6e 63 72 79 70 74 5f 66 69 6c 65 } //1 encrypt_file
		$a_01_2 = {2e 71 37 67 44 50 79 4f 56 37 } //1 .q7gDPyOV7
		$a_01_3 = {72 61 6e 73 6f 6d 5f 6e 6f 74 65 } //1 ransom_note
		$a_01_4 = {65 73 78 63 6c 69 20 76 6d 20 70 72 6f 63 65 73 73 20 6b 69 6c 6c 20 2d 2d 74 79 70 65 3d 66 6f 72 63 65 20 2d 2d 77 6f 72 6c 64 2d 69 64 3d } //1 esxcli vm process kill --type=force --world-id=
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}