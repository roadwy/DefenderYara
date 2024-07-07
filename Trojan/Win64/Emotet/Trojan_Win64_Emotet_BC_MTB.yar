
rule Trojan_Win64_Emotet_BC_MTB{
	meta:
		description = "Trojan:Win64/Emotet.BC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {49 f7 e7 48 c1 ea 90 02 15 4c 89 f1 4c 89 e2 e8 90 01 04 48 89 c1 e8 90 01 04 48 90 02 0f 42 32 04 2f 88 04 3e 48 83 c7 01 48 81 ff 90 01 04 75 90 00 } //1
		$a_01_1 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 DllRegisterServer
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}