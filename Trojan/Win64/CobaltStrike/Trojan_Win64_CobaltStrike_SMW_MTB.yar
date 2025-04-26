
rule Trojan_Win64_CobaltStrike_SMW_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.SMW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {5b 69 5d 20 49 6e 6a 65 63 74 69 6e 67 20 54 68 65 20 52 65 66 6c 65 63 74 69 76 65 20 44 4c 4c 20 49 6e 74 6f } //1 [i] Injecting The Reflective DLL Into
		$a_01_1 = {5b 21 5d 20 43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 20 46 61 69 6c 65 64 20 57 69 74 68 20 45 72 72 6f 72 20 3a } //1 [!] CreateToolhelp32Snapshot Failed With Error :
		$a_01_2 = {52 6c 66 44 6c 6c 49 6e 6a 65 63 74 6f 72 2e 70 64 62 } //1 RlfDllInjector.pdb
		$a_01_3 = {5b 21 5d 20 43 72 65 61 74 65 52 65 6d 6f 74 65 54 68 72 65 61 64 20 46 61 69 6c 65 64 20 57 69 74 68 20 45 72 72 6f 72 3a 20 } //1 [!] CreateRemoteThread Failed With Error: 
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule Trojan_Win64_CobaltStrike_SMW_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.SMW!MTB,SIGNATURE_TYPE_PEHSTR,15 00 15 00 03 00 00 "
		
	strings :
		$a_01_0 = {f3 0f 6f 0a f3 0f 6f 52 10 f3 0f 6f 5a 20 f3 0f 6f 62 30 66 0f 7f 09 66 0f 7f 51 10 66 0f 7f 59 20 66 0f 7f 61 30 f3 0f 6f 4a 40 f3 0f 6f 52 50 f3 0f 6f 5a 60 f3 0f 6f 62 70 66 0f 7f 49 40 66 0f 7f 51 50 66 0f 7f 59 60 66 0f 7f 61 70 48 81 c1 80 00 00 00 48 81 c2 80 00 00 00 49 81 e8 80 00 00 00 49 81 f8 80 00 00 00 73 94 } //10
		$a_01_1 = {45 33 c9 44 8b c0 48 8b 94 24 c0 00 00 00 48 8b 4c 24 48 ff 54 24 68 85 c0 75 07 } //10
		$a_01_2 = {50 61 73 73 77 30 72 64 21 } //1 Passw0rd!
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*1) >=21
 
}