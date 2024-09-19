
rule Trojan_Win64_Cobaltstrike_FB_MTB{
	meta:
		description = "Trojan:Win64/Cobaltstrike.FB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 07 00 00 "
		
	strings :
		$a_03_0 = {8b 04 24 48 89 44 24 ?? 8b 0c 24 33 d2 8b c1 b9 ?? ?? ?? ?? 48 f7 f1 48 8b c2 0f b6 44 04 ?? 48 8b 4c 24 ?? 48 8b 54 24 ?? 0f be 0c 11 33 c8 8b c1 8b 0c 24 48 8b 54 24 ?? 88 04 0a } //15
		$a_81_1 = {66 75 75 75 75 75 63 63 63 63 63 6b 6b 6b 6b 6b 6b 6d 6d 6d 65 65 65 65 } //10 fuuuuuccccckkkkkkmmmeeee
		$a_81_2 = {64 73 73 73 73 73 61 61 61 61 61 69 69 69 69 69 } //1 dsssssaaaaaiiiii
		$a_81_3 = {4c 6f 61 64 52 65 73 6f 75 72 63 65 } //1 LoadResource
		$a_81_4 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //1 IsDebuggerPresent
		$a_81_5 = {43 72 65 61 74 65 46 69 6c 65 41 } //1 CreateFileA
		$a_81_6 = {57 72 69 74 65 46 69 6c 65 } //1 WriteFile
	condition:
		((#a_03_0  & 1)*15+(#a_81_1  & 1)*10+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=15
 
}