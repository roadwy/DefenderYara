
rule Trojan_Win64_CobaltStrike_MH_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.MH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 89 84 24 88 00 00 00 48 8b 8c 24 b8 00 00 00 89 ca bb cd cc cc cc 48 0f af da 48 c1 eb 22 48 89 5c 24 60 48 8b 94 24 b0 00 00 00 31 f6 31 ff 45 31 c0 eb } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win64_CobaltStrike_MH_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.MH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 03 00 00 "
		
	strings :
		$a_01_0 = {0f b6 d1 4d 8d 40 01 33 c2 8b c8 d1 e8 83 e1 01 f7 d9 81 e1 20 83 78 ed 33 c8 8b c1 d1 e9 83 e0 01 f7 d8 25 20 83 78 ed 33 c1 8b c8 d1 e8 } //5
		$a_01_1 = {41 74 6f 6d 4c 64 72 2e 64 6c 6c } //5 AtomLdr.dll
		$a_01_2 = {49 6e 69 74 69 61 6c 69 7a 65 41 74 6f 6d 53 79 73 74 65 6d } //5 InitializeAtomSystem
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5) >=15
 
}
rule Trojan_Win64_CobaltStrike_MH_MTB_3{
	meta:
		description = "Trojan:Win64/CobaltStrike.MH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {41 43 45 45 4e 4d 4a 4b 52 57 54 42 58 64 77 72 57 6c 71 56 6e 50 54 57 51 } //1 ACEENMJKRWTBXdwrWlqVnPTWQ
		$a_01_1 = {41 44 50 6c 62 5a 44 5a 6c 62 6a 72 4f 74 78 66 55 76 71 44 } //1 ADPlbZDZlbjrOtxfUvqD
		$a_01_2 = {41 4e 49 43 6f 41 47 4b 45 75 61 67 46 6c 57 54 66 } //1 ANICoAGKEuagFlWTf
		$a_01_3 = {41 64 70 4b 6b 54 45 4b 45 52 74 78 49 6c 54 56 48 6e 62 6f 77 7a 61 42 66 } //1 AdpKkTEKERtxIlTVHnbowzaBf
		$a_01_4 = {41 6f 45 4d 4d 4f 77 78 4f 45 4f } //1 AoEMMOwxOEO
		$a_01_5 = {41 73 4d 6a 70 6d 7a 62 77 74 55 75 } //1 AsMjpmzbwtUu
		$a_01_6 = {41 75 6e 4f 4f 66 58 49 6e 5a 71 69 74 71 51 77 55 53 66 70 } //1 AunOOfXInZqitqQwUSfp
		$a_01_7 = {41 7a 69 53 52 50 66 57 42 66 6b 5a 52 70 6f } //1 AziSRPfWBfkZRpo
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}