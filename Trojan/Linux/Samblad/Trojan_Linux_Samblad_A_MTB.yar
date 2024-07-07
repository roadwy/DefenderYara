
rule Trojan_Linux_Samblad_A_MTB{
	meta:
		description = "Trojan:Linux/Samblad.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 06 00 00 "
		
	strings :
		$a_00_0 = {73 61 6d 62 61 2d 72 6f 6f 74 2d 73 68 65 6c 6c 63 6f 64 65 2e 63 } //2 samba-root-shellcode.c
		$a_00_1 = {73 61 6d 62 61 2d 72 6f 6f 74 2d 66 69 6e 64 73 6f 63 6b 2e 63 } //2 samba-root-findsock.c
		$a_00_2 = {73 61 6d 62 61 2d 72 6f 6f 74 2d 73 79 73 74 65 6d 2e 63 } //2 samba-root-system.c
		$a_00_3 = {63 68 61 6e 67 65 5f 74 6f 5f 72 6f 6f 74 5f 75 73 65 72 } //1 change_to_root_user
		$a_00_4 = {73 61 6d 62 61 5f 69 6e 69 74 5f 6d 6f 64 75 6c 65 } //1 samba_init_module
		$a_01_5 = {50 41 59 4c 4f 41 44 } //1 PAYLOAD
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_01_5  & 1)*1) >=4
 
}