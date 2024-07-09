
rule Trojan_Win32_TrickBot_I_MTB{
	meta:
		description = "Trojan:Win32/TrickBot.I!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 04 00 00 "
		
	strings :
		$a_03_0 = {8a 45 e6 30 44 0d ?? 41 83 f9 ?? 72 } //10
		$a_03_1 = {73 05 8a 4d 90 0a 0f 00 30 4c 05 ?? 40 83 f8 ?? ?? ?? ?? ?? ?? eb f1 } //10
		$a_03_2 = {89 75 bc 89 4d b0 c7 45 ?? 74 00 2d 00 c7 45 ?? 43 00 6f 00 c7 45 ?? 6f 00 6b 00 c7 45 ?? 69 00 65 00 c7 45 ?? 3a 00 00 00 66 89 45 f4 } //1
		$a_03_3 = {33 c0 66 89 4d c4 c7 45 ?? f6 35 af 35 c7 45 ?? c1 35 ed 35 c7 45 ?? ed 35 e9 35 c7 45 ?? eb 35 e7 35 c7 45 ?? b8 35 82 35 66 89 45 f4 66 31 4c 45 c6 } //1
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=22
 
}