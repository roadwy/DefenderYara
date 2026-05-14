
rule Trojan_Win32_Injector_LMC_MTB{
	meta:
		description = "Trojan:Win32/Injector.LMC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 05 00 00 "
		
	strings :
		$a_81_0 = {63 6d 64 2e 65 78 65 20 2f 63 20 22 25 6c 73 22 } //1 cmd.exe /c "%ls"
		$a_81_1 = {5a 77 54 65 72 6d 69 6e 61 74 65 50 72 6f 63 65 73 73 } //2 ZwTerminateProcess
		$a_81_2 = {43 72 79 70 74 44 65 63 72 79 70 74 } //3 CryptDecrypt
		$a_81_3 = {42 69 6c 6c 73 20 77 69 66 65 20 62 75 79 73 20 68 69 6d 20 61 20 70 72 65 73 65 6e 74 } //4 Bills wife buys him a present
		$a_81_4 = {54 68 6f 73 65 20 70 68 6f 74 6f 67 72 61 70 68 65 72 73 20 73 61 76 65 20 68 69 6d 20 61 20 70 69 65 63 65 20 6f 66 20 70 69 65 } //5 Those photographers save him a piece of pie
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*2+(#a_81_2  & 1)*3+(#a_81_3  & 1)*4+(#a_81_4  & 1)*5) >=15
 
}