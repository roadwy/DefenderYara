
rule Ransom_Linux_Darkside_DA{
	meta:
		description = "Ransom:Linux/Darkside.DA,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_80_0 = {52 65 6d 6f 76 69 6e 67 20 53 65 6c 66 20 45 78 65 63 75 74 61 62 6c 65 2e 2e 2e } //Removing Self Executable...  2
		$a_80_1 = {54 6f 74 61 6c 20 45 6e 63 72 79 70 74 65 64 20 46 69 6c 65 73 2e 2e 2e 2e 2e 2e 2e 2e 2e 2e } //Total Encrypted Files..........  2
		$a_80_2 = {49 67 6e 6f 72 65 64 20 20 56 4d 5b } //Ignored  VM[  1
		$a_80_3 = {6b 69 6c 6c 2d 70 72 6f 63 65 73 73 2e 65 6e 61 62 6c 65 } //kill-process.enable  1
		$a_80_4 = {6b 69 6c 6c 2d 76 6d 2e 65 6e 61 62 6c 65 } //kill-vm.enable  1
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*2+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=5
 
}