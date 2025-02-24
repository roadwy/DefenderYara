
rule Ransom_Linux_Babuk_K_MTB{
	meta:
		description = "Ransom:Linux/Babuk.K!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {66 6f 72 20 69 20 69 6e 20 24 28 65 73 78 63 6c 69 20 76 6d 20 70 72 6f 63 65 73 73 20 6c 69 73 74 } //1 for i in $(esxcli vm process list
		$a_01_1 = {67 72 65 70 20 2d 45 6f 20 27 5b 30 2d 39 5d 7b 31 2c 38 7d 27 29 3b 20 64 6f 20 65 73 78 63 6c 69 20 76 6d 20 70 72 6f 63 65 73 73 20 6b 69 6c 6c 20 2d 74 3d 66 6f 72 63 65 20 2d 77 3d 24 69 3b 20 64 6f 6e 65 } //1 grep -Eo '[0-9]{1,8}'); do esxcli vm process kill -t=force -w=$i; done
		$a_01_2 = {66 6f 72 20 69 20 69 6e 20 24 28 76 69 6d 2d 63 6d 64 20 76 6d 73 76 63 2f 67 65 74 61 6c 6c 76 6d 73 } //1 for i in $(vim-cmd vmsvc/getallvms
		$a_01_3 = {67 72 65 70 20 2d 45 6f 20 27 5b 30 2d 39 5d 7b 31 2c 38 7d 27 29 3b 20 64 6f 20 76 69 6d 2d 63 6d 64 20 76 6d 73 76 63 2f 73 6e 61 70 73 68 6f 74 2e 72 65 6d 6f 76 65 61 6c 6c 20 24 69 3b 20 64 6f 6e 65 } //1 grep -Eo '[0-9]{1,8}'); do vim-cmd vmsvc/snapshot.removeall $i; done
		$a_01_4 = {5d 5d 3b 20 74 68 65 6e 20 76 69 6d 2d 63 6d 64 20 76 6d 73 76 63 2f 70 6f 77 65 72 2e 6f 66 66 20 24 69 3b 20 66 69 3b 20 64 6f 6e 65 } //1 ]]; then vim-cmd vmsvc/power.off $i; fi; done
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}