
rule Trojan_Win64_Rozena_SXC_MTB{
	meta:
		description = "Trojan:Win64/Rozena.SXC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,2c 00 2c 00 07 00 00 "
		
	strings :
		$a_80_0 = {49 6e 6a 65 63 74 20 44 4c 4c } //Inject DLL  10
		$a_80_1 = {49 6e 6a 65 63 74 70 72 6f 63 65 73 73 5f 62 79 5f 74 68 72 65 61 64 48 69 6a 61 63 6b 65 64 } //Injectprocess_by_threadHijacked  10
		$a_80_2 = {41 50 43 5f 69 6e 6a 65 63 74 } //APC_inject  10
		$a_80_3 = {72 75 6e 5f 73 68 65 6c 6c 63 6f 64 65 } //run_shellcode  5
		$a_80_4 = {65 78 65 63 75 74 65 5f 77 69 74 68 5f 4e 74 54 65 73 74 41 6c 65 72 74 } //execute_with_NtTestAlert  5
		$a_80_5 = {45 61 72 6c 79 42 69 72 64 49 6e 6a 65 63 74 } //EarlyBirdInject  2
		$a_80_6 = {45 78 65 63 75 74 65 20 53 75 63 63 65 73 73 } //Execute Success  2
	condition:
		((#a_80_0  & 1)*10+(#a_80_1  & 1)*10+(#a_80_2  & 1)*10+(#a_80_3  & 1)*5+(#a_80_4  & 1)*5+(#a_80_5  & 1)*2+(#a_80_6  & 1)*2) >=44
 
}