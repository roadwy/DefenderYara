
rule TrojanDownloader_Linux_Samdown{
	meta:
		description = "TrojanDownloader:Linux/Samdown,SIGNATURE_TYPE_ELFHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_00_0 = {73 70 61 77 6e 5f 72 65 76 65 72 73 65 5f 73 68 65 6c 6c } //4 spawn_reverse_shell
		$a_00_1 = {73 61 6d 62 61 5f 69 6e 69 74 5f 6d 6f 64 75 6c 65 } //2 samba_init_module
		$a_00_2 = {63 68 61 6e 67 65 5f 74 6f 5f 72 6f 6f 74 5f 75 73 65 72 } //2 change_to_root_user
		$a_00_3 = {48 65 6c 6c 6f 20 66 72 6f 6d 20 74 68 65 20 53 61 6d 62 61 } //2 Hello from the Samba
	condition:
		((#a_00_0  & 1)*4+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2+(#a_00_3  & 1)*2) >=8
 
}