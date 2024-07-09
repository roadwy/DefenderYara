
rule Trojan_Win64_CobaltStrike_BK_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.BK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 8b c3 4d 8d 40 ?? 48 f7 e1 41 ff c2 48 c1 ea ?? 48 6b c2 ?? 48 2b c8 0f b6 44 8c ?? 41 30 40 ?? 49 63 ca 48 81 f9 ?? ?? ?? ?? 72 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win64_CobaltStrike_BK_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.BK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {f2 0f 11 44 24 ?? 66 ?? ?? ?? ?? ?? ?? ?? ?? fe 4c 15 ?? 33 c0 0f b6 4c 15 ?? 48 ?? ?? ?? 49 ?? ?? ?? 49 ?? ?? ?? 41 ?? ?? 32 4c 04 ?? 4c 8d 48 ?? 88 8c 15 ?? ?? ?? ?? 41 ?? ?? ?? ?? ?? ?? 72 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win64_CobaltStrike_BK_MTB_3{
	meta:
		description = "Trojan:Win64/CobaltStrike.BK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {c1 c9 08 e8 [0-04] 41 0f b6 0c 3c 31 c1 41 33 0e 49 ff c5 41 89 4e 20 49 83 fd 08 75 06 48 ff c7 45 31 ed 49 83 c6 04 4c 39 f5 75 } //2
		$a_01_1 = {63 6d 64 20 2f 63 20 43 3a 5c 57 69 6e 64 6f 77 73 5c 54 65 6d 70 } //2 cmd /c C:\Windows\Temp
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}