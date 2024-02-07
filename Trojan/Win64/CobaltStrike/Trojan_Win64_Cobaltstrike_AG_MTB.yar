
rule Trojan_Win64_Cobaltstrike_AG_MTB{
	meta:
		description = "Trojan:Win64/Cobaltstrike.AG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {62 79 70 61 73 73 5c 43 61 6c 6c 44 4c 4c 44 79 6e 61 6d 69 63 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 74 65 73 74 44 4c 4c 2e 70 64 62 } //01 00  bypass\CallDLLDynamic\x64\Release\testDLL.pdb
		$a_01_1 = {74 65 73 74 44 4c 4c 2e 64 6c 6c } //00 00  testDLL.dll
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_Cobaltstrike_AG_MTB_2{
	meta:
		description = "Trojan:Win64/Cobaltstrike.AG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {48 ff c7 ff c5 41 f7 e9 c1 fa 02 8b c2 c1 e8 1f 03 d0 0f b6 c2 c0 e0 02 8d 0c 10 02 c9 44 2a c9 41 80 c9 30 44 88 4c 3c 1f 44 8b ca 85 d2 75 cb } //01 00 
		$a_01_1 = {4a 47 41 4e 56 2a 54 28 58 42 } //00 00  JGANV*T(XB
	condition:
		any of ($a_*)
 
}