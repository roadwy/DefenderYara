
rule Ransom_Win64_BlackBasta_NUA_MTB{
	meta:
		description = "Ransom:Win64/BlackBasta.NUA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_81_0 = {59 6f 75 20 63 61 6e 20 63 6f 6e 74 61 63 74 20 75 73 20 61 6e 64 20 64 65 63 72 79 70 74 20 6f 6e 65 20 66 69 6c 65 } //1 You can contact us and decrypt one file
		$a_81_1 = {7a 59 63 62 52 4c 31 61 6f 65 66 34 67 62 62 68 4f 58 50 76 4b 6c 34 50 6d 4b 58 37 72 62 64 47 58 4c } //1 zYcbRL1aoef4gbbhOXPvKl4PmKX7rbdGXL
		$a_81_2 = {59 6f 75 72 20 64 61 74 61 20 61 72 65 20 73 74 6f 6c 65 6e 20 61 6e 64 20 65 6e 63 72 79 70 74 65 64 } //1 Your data are stolen and encrypted
		$a_81_3 = {44 6f 6e 65 20 74 69 6d 65 3a 20 25 2e 34 66 20 73 65 63 6f 6e 64 73 2c 20 65 6e 63 72 79 70 74 65 64 3a 20 25 2e 34 66 20 67 62 } //1 Done time: %.4f seconds, encrypted: %.4f gb
		$a_81_4 = {43 3a 5c 57 69 6e 64 6f 77 73 5c 53 79 73 4e 61 74 69 76 65 5c 76 73 73 61 64 6d 69 6e 2e 65 78 65 20 64 65 6c 65 74 65 20 73 68 61 64 6f 77 73 20 2f 61 6c 6c 20 2f 71 75 69 65 74 } //2 C:\Windows\SysNative\vssadmin.exe delete shadows /all /quiet
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*2) >=6
 
}