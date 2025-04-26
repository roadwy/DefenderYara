
rule Trojan_Win64_StealthWorm_DA_MTB{
	meta:
		description = "Trojan:Win64/StealthWorm.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,18 00 18 00 06 00 00 "
		
	strings :
		$a_80_0 = {57 69 70 69 6e 67 20 73 79 73 74 65 6d 2e 2e 2e } //Wiping system...  10
		$a_80_1 = {43 3a 5c 57 69 6e 64 6f 77 73 5c 4d 65 6d 6f 72 79 2e 64 6d 70 } //C:\Windows\Memory.dmp  1
		$a_80_2 = {44 65 6c 65 74 65 64 20 66 69 6c 65 3a } //Deleted file:  10
		$a_80_3 = {43 3a 5c 68 69 62 65 72 66 69 6c 2e 73 79 73 } //C:\hiberfil.sys  1
		$a_80_4 = {4e 6f 20 74 68 72 65 61 74 73 20 64 65 74 65 63 74 65 64 2e } //No threats detected.  1
		$a_80_5 = {46 61 69 6c 65 64 20 74 6f 20 64 65 6c 65 74 65 20 64 69 72 65 63 74 6f 72 79 3a } //Failed to delete directory:  1
	condition:
		((#a_80_0  & 1)*10+(#a_80_1  & 1)*1+(#a_80_2  & 1)*10+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1) >=24
 
}