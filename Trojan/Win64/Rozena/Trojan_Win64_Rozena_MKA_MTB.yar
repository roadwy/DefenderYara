
rule Trojan_Win64_Rozena_MKA_MTB{
	meta:
		description = "Trojan:Win64/Rozena.MKA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,37 00 37 00 06 00 00 "
		
	strings :
		$a_81_0 = {5a 51 41 5f 53 48 45 4c 4c 43 4f 44 45 } //20 ZQA_SHELLCODE
		$a_81_1 = {41 50 43 5f 69 6e 6a 65 63 74 } //15 APC_inject
		$a_81_2 = {49 6e 6a 65 63 74 70 72 6f 63 65 73 73 5f 62 79 5f 74 68 72 65 61 64 48 69 6a 61 63 6b 65 64 } //10 Injectprocess_by_threadHijacked
		$a_81_3 = {5b 2a 5d 20 49 6e 6a 65 63 74 20 44 4c 4c 3a } //5 [*] Inject DLL:
		$a_81_4 = {5b 2a 5d 20 49 6e 6a 65 63 74 69 6e 67 20 74 6f 20 50 49 44 3a } //3 [*] Injecting to PID:
		$a_81_5 = {5b 2a 5d 20 43 72 65 61 74 65 54 68 72 65 61 64 20 48 6f 6f 6b 65 64 } //3 [*] CreateThread Hooked
	condition:
		((#a_81_0  & 1)*20+(#a_81_1  & 1)*15+(#a_81_2  & 1)*10+(#a_81_3  & 1)*5+(#a_81_4  & 1)*3+(#a_81_5  & 1)*3) >=55
 
}