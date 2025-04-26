
rule Trojan_Win64_IcedID_ZA_MTB{
	meta:
		description = "Trojan:Win64/IcedID.ZA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c6 c1 e2 ?? 2b c2 41 ?? ?? ?? 41 ?? ?? 41 ?? ?? ?? 03 c8 48 ?? ?? ?? ?? 03 cb ff c3 48 ?? ?? 42 ?? ?? ?? ?? ?? ?? ?? ?? 41 ?? ?? ?? ?? 41 ?? ?? ?? ?? 3b 5c 24 ?? 72 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win64_IcedID_ZA_MTB_2{
	meta:
		description = "Trojan:Win64/IcedID.ZA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {66 89 44 24 ?? b8 5a 00 00 00 e9 ?? ?? ?? ?? b8 02 00 00 00 83 c0 74 66 3b e4 74 ?? 66 89 44 24 6a b8 44 00 00 00 66 3b f6 74 ?? 66 89 44 24 6e b8 5f 00 00 00 66 3b c0 74 } //1
		$a_01_1 = {63 61 73 74 66 64 61 73 75 64 68 79 75 67 61 77 75 6a 64 62 79 61 75 } //1 castfdasudhyugawujdbyau
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}