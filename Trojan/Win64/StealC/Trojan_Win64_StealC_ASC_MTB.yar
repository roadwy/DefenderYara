
rule Trojan_Win64_StealC_ASC_MTB{
	meta:
		description = "Trojan:Win64/StealC.ASC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 06 00 00 "
		
	strings :
		$a_03_0 = {2f 00 2f 00 79 00 7a 00 67 00 79 00 2e 00 63 00 63 00 2f 00 [0-0f] 2e 00 62 00 69 00 6e 00 } //5
		$a_03_1 = {2f 00 2f 00 64 00 6d 00 73 00 73 00 39 00 39 00 39 00 2e 00 63 00 6f 00 6d 00 2f 00 [0-0f] 2e 00 62 00 69 00 6e 00 } //5
		$a_80_2 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } //VirtualAllocEx  1
		$a_80_3 = {52 65 73 75 6d 65 54 68 72 65 61 64 } //ResumeThread  1
		$a_80_4 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //WriteProcessMemory  1
		$a_80_5 = {5c 55 73 5c 4a 48 2e 65 78 65 20 2f 63 72 65 61 74 65 20 2f 73 63 20 6f 6e 6c 6f 67 6f 6e 20 2f 74 6e 20 56 69 70 20 2f 72 6c 20 68 69 67 68 65 73 74 20 2f 74 72 } //\Us\JH.exe /create /sc onlogon /tn Vip /rl highest /tr  1
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1) >=14
 
}