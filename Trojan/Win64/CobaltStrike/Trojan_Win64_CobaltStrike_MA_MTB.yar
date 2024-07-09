
rule Trojan_Win64_CobaltStrike_MA_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 "
		
	strings :
		$a_03_0 = {f7 ee ff c6 c1 fa 03 8b c2 c1 e8 1f 03 d0 6b c2 11 2b c8 48 63 c1 48 8d 0d ?? ?? ?? ?? 8a 04 08 43 32 04 02 41 88 00 49 ff c0 3b f3 72 cb } //5
		$a_01_1 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //2 DllRegisterServer
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*2) >=7
 
}
rule Trojan_Win64_CobaltStrike_MA_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f af 48 68 8b c1 89 44 24 34 8b 44 24 34 c1 e8 10 48 8b 8c 24 [0-04] 48 63 49 6c 48 8b 94 24 [0-04] 48 8b 92 a0 00 00 00 88 04 0a 48 8b 84 24 [0-04] 8b 40 6c ff c0 48 8b 8c 24 [0-04] 89 41 6c 8b 44 24 34 c1 e8 08 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}