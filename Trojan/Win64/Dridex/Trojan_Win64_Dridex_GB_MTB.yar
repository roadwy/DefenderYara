
rule Trojan_Win64_Dridex_GB_MTB{
	meta:
		description = "Trojan:Win64/Dridex.GB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_80_0 = {68 61 6c 66 62 75 6c 6c 73 68 69 74 54 78 43 } //halfbullshitTxC  1
		$a_80_1 = {62 4a 61 6e 75 61 72 79 74 79 70 69 63 61 6c 6c 79 70 61 74 63 68 34 64 61 74 61 } //bJanuarytypicallypatch4data  1
		$a_80_2 = {7a 45 53 65 63 75 72 69 74 79 71 4f 6e } //zESecurityqOn  1
		$a_80_3 = {78 47 6f 6f 67 6c 65 6f 51 74 68 65 75 61 46 65 62 72 75 61 72 79 30 62 72 6f 77 73 65 72 } //xGoogleoQtheuaFebruary0browser  1
		$a_80_4 = {72 61 61 77 70 75 62 6c 69 73 68 65 64 30 4f 70 65 72 61 4a 61 76 61 53 63 72 69 70 74 } //raawpublished0OperaJavaScript  1
		$a_80_5 = {74 69 70 73 51 50 43 77 68 6f 77 65 6c 63 6f 6d 65 } //tipsQPCwhowelcome  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1) >=6
 
}
rule Trojan_Win64_Dridex_GB_MTB_2{
	meta:
		description = "Trojan:Win64/Dridex.GB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 03 00 00 "
		
	strings :
		$a_02_0 = {45 8a 1c 12 45 28 cb 48 8b 54 24 ?? 44 8a 4c 24 ?? 44 88 8c 24 [0-04] 4c 29 c1 8b 44 24 ?? 0f af c0 89 84 24 [0-04] 4c 8b 44 24 48 45 88 1c 10 48 03 4c 24 ?? 66 8b 74 24 ?? 66 29 f6 66 89 b4 24 [0-04] 48 8b 94 24 [0-04] 48 89 4c 24 ?? 48 39 d1 0f 85 } //10
		$a_02_1 = {89 c1 48 8d 15 [0-04] 8b 44 24 ?? 89 84 24 [0-04] 4c 8b 44 24 ?? 44 8a 4c 24 ?? 41 80 f1 ff } //10
		$a_80_2 = {72 61 69 73 69 6e 67 6e 35 38 37 } //raisingn587  1
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10+(#a_80_2  & 1)*1) >=21
 
}