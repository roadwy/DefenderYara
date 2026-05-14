
rule Trojan_Win64_Convagent_KK_MTB{
	meta:
		description = "Trojan:Win64/Convagent.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 63 44 24 20 48 8b 4c 24 40 0f b6 04 01 89 44 24 28 8b 44 24 20 99 f7 7c 24 24 8b c2 48 98 48 8b 4c 24 50 0f b6 04 01 8b 4c 24 28 33 c8 8b c1 48 63 4c 24 20 48 8b 54 24 48 88 04 0a 8b 44 24 20 ff c0 89 44 24 20 } //20
	condition:
		((#a_01_0  & 1)*20) >=20
 
}
rule Trojan_Win64_Convagent_KK_MTB_2{
	meta:
		description = "Trojan:Win64/Convagent.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,29 00 29 00 06 00 00 "
		
	strings :
		$a_01_0 = {0f be 14 08 66 89 54 45 d0 48 83 c0 01 48 83 f8 05 } //20
		$a_01_1 = {0f b7 07 35 49 8b 00 00 0f b6 4f 02 81 f1 c8 00 00 00 66 09 c1 } //10
		$a_01_2 = {4d 65 6d 6f 72 79 20 63 68 61 6e 67 65 64 20 74 6f 20 50 41 47 45 5f 45 58 45 43 55 54 45 5f 52 45 41 44 } //5 Memory changed to PAGE_EXECUTE_READ
		$a_01_3 = {53 65 61 72 63 68 69 6e 67 20 66 6f 72 20 73 79 73 63 61 6c 6c } //3 Searching for syscall
		$a_01_4 = {46 61 69 6c 65 64 20 74 6f 20 66 69 6e 64 20 27 6d 6f 76 20 72 63 78 2c 20 72 38 27 20 70 61 74 74 65 72 6e } //2 Failed to find 'mov rcx, r8' pattern
		$a_01_5 = {52 65 73 6f 6c 76 65 64 20 42 61 73 65 54 68 72 65 61 64 49 6e 69 74 58 46 47 54 68 75 6e 6b } //1 Resolved BaseThreadInitXFGThunk
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*10+(#a_01_2  & 1)*5+(#a_01_3  & 1)*3+(#a_01_4  & 1)*2+(#a_01_5  & 1)*1) >=41
 
}