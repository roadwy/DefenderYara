
rule Trojan_Win64_Tnega_DA_MTB{
	meta:
		description = "Trojan:Win64/Tnega.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,18 00 18 00 06 00 00 "
		
	strings :
		$a_80_0 = {77 6d 69 63 63 6f 6d 70 75 74 65 72 73 79 73 74 65 6d 67 65 74 6d 6f 64 65 6c 46 61 69 6c 65 64 } //wmiccomputersystemgetmodelFailed  10
		$a_80_1 = {61 65 73 5f 65 6e 63 72 79 70 74 } //aes_encrypt  1
		$a_80_2 = {70 6f 77 65 72 73 68 65 6c 6c 43 6c 65 61 72 2d 45 76 65 6e 74 4c 6f 67 } //powershellClear-EventLog  10
		$a_80_3 = {45 6e 63 72 79 70 74 65 64 3a } //Encrypted:  1
		$a_80_4 = {56 69 72 74 75 61 6c 42 6f 78 } //VirtualBox  1
		$a_80_5 = {56 4d 77 61 72 65 } //VMware  1
	condition:
		((#a_80_0  & 1)*10+(#a_80_1  & 1)*1+(#a_80_2  & 1)*10+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1) >=24
 
}