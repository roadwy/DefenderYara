
rule Trojan_Win32_Ursnif_RC_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.RC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 44 24 40 8b 4c 24 2c 01 44 24 24 0f af c8 8b 44 24 24 2b c1 a3 } //1
		$a_01_1 = {48 3a 5c 66 6c 6f 77 5c 72 65 70 72 6f 64 75 63 74 69 76 69 74 79 5c 61 63 74 5c 73 63 72 69 70 74 73 2e 70 64 62 } //1 H:\flow\reproductivity\act\scripts.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Ursnif_RC_MTB_2{
	meta:
		description = "Trojan:Win32/Ursnif.RC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {2b d9 01 1d ?? ?? ?? ?? 8b 5c 24 ?? 33 c9 85 d2 0f 94 c1 85 c9 74 ?? 2b ca } //1
		$a_02_1 = {2b c8 03 f1 8b c8 2b ce 83 c1 ?? 8d 84 00 ?? ?? ?? ?? 2b c1 03 c6 83 3d ?? ?? ?? ?? ?? 89 0d ?? ?? ?? ?? a3 ?? ?? ?? ?? 75 ?? 8d 4e ?? 03 f6 2b f0 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}