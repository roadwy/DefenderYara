
rule Ransom_Linux_RansomESX_A{
	meta:
		description = "Ransom:Linux/RansomESX.A,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {65 73 78 63 6c 69 20 76 6d 20 70 72 6f 63 65 73 73 20 6b 69 6c 6c 20 2d 74 3d 73 6f 66 74 20 2d 77 3d 25 64 } //1 esxcli vm process kill -t=soft -w=%d
		$a_00_1 = {65 73 78 63 6c 69 20 76 6d 20 70 72 6f 63 65 73 73 20 6b 69 6c 6c 20 2d 74 3d 66 6f 72 63 65 20 2d 77 3d 25 64 } //1 esxcli vm process kill -t=force -w=%d
		$a_00_2 = {65 73 78 63 6c 69 20 76 6d 20 70 72 6f 63 65 73 73 20 6b 69 6c 6c 20 2d 74 3d 68 61 72 64 20 2d 77 3d 25 64 } //1 esxcli vm process kill -t=hard -w=%d
		$a_00_3 = {65 73 78 63 6c 69 20 76 6d 20 70 72 6f 63 65 73 73 20 6c 69 73 74 } //1 esxcli vm process list
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}