
rule Ransom_Linux_RevilCrypt_PA_MTB{
	meta:
		description = "Ransom:Linux/RevilCrypt.PA!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {52 65 76 69 78 20 31 2e 31 63 } //1 Revix 1.1c
		$a_01_1 = {65 6c 66 2e 65 78 65 20 2d 2d 70 61 74 68 20 2f 76 6d 66 73 2f 20 2d 2d 74 68 72 65 61 64 73 20 35 } //1 elf.exe --path /vmfs/ --threads 5
		$a_01_2 = {73 79 73 74 65 6d 28 22 65 73 78 63 6c 69 20 76 6d 20 70 72 6f 63 65 73 73 20 6b 69 6c 6c 20 2d 2d 74 79 70 65 3d 66 6f 72 63 65 20 2d 2d 77 6f 72 6c 64 2d 69 64 3d 22 20 24 31 29 } //1 system("esxcli vm process kill --type=force --world-id=" $1)
		$a_01_3 = {69 6a 69 20 69 6a 69 20 69 6a 69 20 69 6a 69 20 69 6a 7c 20 45 4e 43 52 59 50 54 45 44 20 7c 6a 69 20 69 6a 69 20 69 66 69 20 69 6a 69 20 69 6a 69 20 69 6a 69 } //1 iji iji iji iji ij| ENCRYPTED |ji iji ifi iji iji iji
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}