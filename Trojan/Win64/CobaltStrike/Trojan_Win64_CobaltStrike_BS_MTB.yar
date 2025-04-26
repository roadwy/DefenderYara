
rule Trojan_Win64_CobaltStrike_BS_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.BS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 04 24 48 8b 4c 24 20 0f be 44 01 04 48 8b 4c 24 20 0f b6 49 0b 2b c1 48 8b 4c 24 20 0f b6 49 0a 33 c1 8b 0c 24 48 8b 54 24 08 88 04 0a eb } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}
rule Trojan_Win64_CobaltStrike_BS_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.BS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {31 c0 39 c2 7e ?? 49 89 c1 41 83 e1 ?? 47 ?? ?? ?? 44 30 0c 01 48 ff c0 eb ?? 4c 8d 05 ?? ?? ?? ?? e9 } //1
		$a_00_1 = {44 6c 6c 47 65 74 43 6c 61 73 73 4f 62 6a 65 63 74 } //1 DllGetClassObject
		$a_00_2 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 DllRegisterServer
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}
rule Trojan_Win64_CobaltStrike_BS_MTB_3{
	meta:
		description = "Trojan:Win64/CobaltStrike.BS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 8b 44 24 ?? 0f b6 00 0f b6 4c 24 ?? 33 c1 48 8b 8c 24 ?? ?? ?? ?? 48 8b 54 24 ?? 48 2b d1 48 8b ca 0f b6 c9 81 e1 [0-04] 33 c1 48 8b 4c 24 ?? 88 01 48 63 44 24 ?? 48 8b 4c 24 ?? 48 03 c8 48 8b c1 48 89 44 24 ?? e9 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win64_CobaltStrike_BS_MTB_4{
	meta:
		description = "Trojan:Win64/CobaltStrike.BS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {44 89 ee 48 c1 ee ?? 42 ?? ?? ?? ?? c1 e3 ?? c1 e1 ?? 09 d9 41 c1 e0 ?? 41 09 c8 41 09 f0 4c 8b b5 ?? ?? ?? ?? 41 0f c8 44 33 85 ?? ?? ?? ?? 48 89 c1 } //1
		$a_03_1 = {48 39 c6 74 ?? 48 39 c1 0f 84 ?? ?? ?? ?? 8a 1c 07 41 30 1c 06 48 ff c0 eb } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_Win64_CobaltStrike_BS_MTB_5{
	meta:
		description = "Trojan:Win64/CobaltStrike.BS!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f b6 45 d9 04 31 34 63 88 45 da 0f b6 45 da 04 31 34 75 88 45 db } //1
		$a_01_1 = {0f b6 54 05 d0 41 80 c0 31 0f b6 4c 05 d0 41 32 c8 44 0f b6 c2 88 4c 05 d0 48 ff c0 48 83 f8 11 72 de } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}