
rule Trojan_Win64_CryptInject_RR_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.RR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {43 61 73 74 65 6c 61 44 4c 4c 2e 64 6c 6c } //1 CastelaDLL.dll
		$a_00_1 = {4d 00 69 00 6e 00 48 00 6f 00 6f 00 6b 00 20 00 44 00 4c 00 4c 00 } //1 MinHook DLL
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}