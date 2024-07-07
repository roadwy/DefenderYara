
rule Ransom_Linux_HelloKitty_A{
	meta:
		description = "Ransom:Linux/HelloKitty.A,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 06 00 00 "
		
	strings :
		$a_01_0 = {2e 52 45 41 44 4d 45 5f 54 4f 5f 52 45 53 54 4f 52 45 } //1 .README_TO_RESTORE
		$a_01_1 = {52 75 6e 6e 69 6e 67 20 56 4d 3a 25 6c 64 } //1 Running VM:%ld
		$a_01_2 = {46 69 6e 64 20 45 53 58 69 3a 25 73 } //1 Find ESXi:%s
		$a_00_3 = {65 73 78 63 6c 69 20 76 6d 20 70 72 6f 63 65 73 73 20 6b 69 6c 6c 20 2d 74 3d 66 6f 72 63 65 20 2d 77 3d 25 64 } //1 esxcli vm process kill -t=force -w=%d
		$a_01_4 = {55 73 61 67 65 3a 25 73 20 5b 2d 6d 20 28 31 30 2d 32 30 2d 32 35 2d 33 33 2d 35 30 29 20 5d 20 53 74 61 72 74 20 50 61 74 68 } //1 Usage:%s [-m (10-20-25-33-50) ] Start Path
		$a_01_5 = {65 72 72 6f 72 20 65 6e 63 72 79 70 74 3a 20 25 73 20 72 65 6e 61 6d 65 20 62 61 63 6b 3a 25 73 } //1 error encrypt: %s rename back:%s
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=4
 
}