
rule Trojan_Win64_DelShad_SK_MTB{
	meta:
		description = "Trojan:Win64/DelShad.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {2f 63 20 76 73 73 61 64 6d 69 6e 20 64 65 6c 65 74 65 20 73 68 61 64 6f 77 73 20 2f 61 6c 6c 20 2f 71 75 69 65 74 } //1 /c vssadmin delete shadows /all /quiet
		$a_01_1 = {50 72 6f 67 72 61 6d 44 61 74 61 5c 73 65 73 73 69 6f 6e 75 73 65 72 68 6f 73 74 2e 65 78 65 20 2f 73 63 20 6f 6e 6c 6f 67 6f 6e 20 2f 72 6c 20 48 49 47 48 45 53 54 } //1 ProgramData\sessionuserhost.exe /sc onlogon /rl HIGHEST
		$a_01_2 = {53 50 47 5c 73 6f 75 72 63 65 5c 72 65 70 6f 73 5c 6c 6f 61 64 65 72 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 73 65 73 73 69 6f 6e 75 73 65 72 68 6f 73 74 2e 70 64 62 } //1 SPG\source\repos\loader\x64\Release\sessionuserhost.pdb
		$a_01_3 = {73 65 73 73 69 6f 6e 75 73 65 72 68 6f 73 74 2e 65 78 65 } //1 sessionuserhost.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}