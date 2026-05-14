
rule Trojan_Win64_Tedy_LMV_MTB{
	meta:
		description = "Trojan:Win64/Tedy.LMV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 04 00 00 "
		
	strings :
		$a_81_0 = {52 65 66 6c 65 63 74 69 76 65 4c 6f 61 64 65 72 40 40 59 41 5f 4b 50 45 41 58 40 5a } //1 ReflectiveLoader@@YA_KPEAX@Z
		$a_81_1 = {5b 45 4e 56 5d 20 53 65 61 72 63 68 20 73 74 72 69 6e 67 20 6c 65 6e 67 74 68 3a 20 25 7a 75 20 63 68 61 72 61 63 74 65 72 73 } //2 [ENV] Search string length: %zu characters
		$a_81_2 = {43 52 49 54 49 43 41 4c 20 45 58 43 45 50 54 49 4f 4e 3a 20 48 6f 6f 6b 20 69 6e 73 74 61 6c 6c 61 74 69 6f 6e 20 66 61 69 6c 65 64 } //3 CRITICAL EXCEPTION: Hook installation failed
		$a_81_3 = {48 56 4e 43 49 6e 6a 65 63 74 69 6f 6e 2e 78 36 34 } //4 HVNCInjection.x64
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*2+(#a_81_2  & 1)*3+(#a_81_3  & 1)*4) >=10
 
}