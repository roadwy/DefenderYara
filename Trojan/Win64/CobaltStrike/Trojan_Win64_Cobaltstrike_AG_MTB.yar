
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
rule Trojan_Win64_Cobaltstrike_AG_MTB_3{
	meta:
		description = "Trojan:Win64/Cobaltstrike.AG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 04 00 "
		
	strings :
		$a_03_0 = {0f b6 84 04 90 01 04 48 8b 4c 24 90 01 01 0f b6 09 33 c8 8b c1 48 8b 4c 24 90 01 01 88 01 8b 44 24 20 ff c0 89 44 24 20 8b 44 24 20 83 e0 07 89 44 24 20 eb 90 00 } //01 00 
		$a_01_1 = {52 64 76 53 65 72 76 69 63 65 4d 61 69 6e 40 40 59 41 58 50 45 41 58 30 4b 30 4b 40 5a } //00 00  RdvServiceMain@@YAXPEAX0K0K@Z
	condition:
		any of ($a_*)
 
}