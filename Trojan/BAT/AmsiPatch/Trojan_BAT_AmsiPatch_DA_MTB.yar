
rule Trojan_BAT_AmsiPatch_DA_MTB{
	meta:
		description = "Trojan:BAT/AmsiPatch.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,68 00 68 00 05 00 00 "
		
	strings :
		$a_81_0 = {49 6e 6a 65 63 74 69 6e 67 20 56 4d 20 68 6f 6f 6b 20 63 6f 64 65 } //100 Injecting VM hook code
		$a_81_1 = {53 6f 70 68 6f 73 41 6d 73 69 50 72 6f 76 69 64 65 72 2e 64 6c 6c } //1 SophosAmsiProvider.dll
		$a_81_2 = {63 6f 6d 5f 61 6e 74 69 76 69 72 75 73 2e 64 6c 6c } //1 com_antivirus.dll
		$a_81_3 = {4d 61 6c 77 61 72 65 62 79 74 65 73 } //1 Malwarebytes
		$a_81_4 = {5b 65 61 78 2b 65 62 78 5d } //1 [eax+ebx]
	condition:
		((#a_81_0  & 1)*100+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=104
 
}