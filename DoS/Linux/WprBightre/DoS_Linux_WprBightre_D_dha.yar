
rule DoS_Linux_WprBightre_D_dha{
	meta:
		description = "DoS:Linux/WprBightre.D!dha,SIGNATURE_TYPE_ELFHSTR_EXT,06 00 06 00 07 00 00 "
		
	strings :
		$a_00_0 = {5b 21 5d 20 57 61 69 74 69 6e 67 20 46 6f 72 20 20 51 75 65 75 65 } //1 [!] Waiting For  Queue
		$a_00_1 = {44 65 6c 65 74 69 6e 67 20 44 69 73 6b 73 2e 2e 2e } //1 Deleting Disks...
		$a_00_2 = {44 69 73 6b 4e 61 6d 65 3a 20 25 73 2c 20 44 65 6c 65 74 65 64 3a 20 25 64 20 2d 20 25 64 } //1 DiskName: %s, Deleted: %d - %d
		$a_00_3 = {5b 2b 5d 20 52 6f 75 6e 64 20 25 64 } //1 [+] Round %d
		$a_00_4 = {49 73 72 61 65 6c } //1 Israel
		$a_00_5 = {5b 2b 5d 20 4f 4b 2c 20 49 74 20 77 61 73 6e 27 74 20 2e 2e 2e } //1 [+] OK, It wasn't ...
		$a_00_6 = {5b 2b 5d 20 43 50 55 20 63 6f 72 65 73 3a 20 25 64 2c 20 54 68 72 65 61 64 73 3a 20 25 64 } //1 [+] CPU cores: %d, Threads: %d
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=6
 
}