
rule Trojan_Win64_CryptInject_CL_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.CL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 06 00 00 "
		
	strings :
		$a_01_0 = {52 65 6c 65 61 73 65 5c 49 6e 6a 65 63 74 6f 72 2e 70 64 62 } //2 Release\Injector.pdb
		$a_01_1 = {49 6e 6a 65 63 74 65 64 20 73 75 63 63 65 73 73 66 75 6c 6c 79 } //2 Injected successfully
		$a_01_2 = {53 75 63 63 65 73 73 66 75 6c 6c 79 20 69 6e 6a 65 63 74 65 64 21 } //2 Successfully injected!
		$a_01_3 = {43 61 6e 27 74 20 77 72 69 74 65 20 73 68 65 6c 6c 63 6f 64 65 } //2 Can't write shellcode
		$a_01_4 = {63 61 6e 27 74 20 72 65 6c 65 61 73 65 20 73 68 65 6c 6c 20 63 6f 64 65 20 6d 65 6d 6f 72 79 } //2 can't release shell code memory
		$a_01_5 = {63 61 6e 27 74 20 72 65 6c 65 61 73 65 20 6d 61 70 70 69 6e 67 20 64 61 74 61 20 6d 65 6d 6f 72 79 } //2 can't release mapping data memory
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2) >=10
 
}