
rule Trojan_Linux_Torchion_A{
	meta:
		description = "Trojan:Linux/Torchion.A,SIGNATURE_TYPE_ELFHSTR_EXT,17 00 17 00 07 00 00 "
		
	strings :
		$a_01_0 = {2f 65 74 63 2f 72 65 73 6f 6c 76 2e 63 6f 6e 66 } //1 /etc/resolv.conf
		$a_01_1 = {2f 65 74 63 2f 68 6f 73 74 73 } //1 /etc/hosts
		$a_01_2 = {2f 65 74 63 2f 70 61 73 73 77 64 } //1 /etc/passwd
		$a_01_3 = {2e 73 73 68 } //1 .ssh
		$a_01_4 = {2e 67 69 74 63 6f 6e 66 69 67 } //1 .gitconfig
		$a_01_5 = {67 65 74 4e 61 6d 65 73 65 72 76 65 72 73 } //10 getNameservers
		$a_01_6 = {67 61 74 68 65 72 46 69 6c 65 73 } //10 gatherFiles
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*10+(#a_01_6  & 1)*10) >=23
 
}