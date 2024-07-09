
rule Trojan_Win32_SmokeLoader_ASM_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.ASM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {6a 00 6a 00 ff 15 ?? ?? ?? ?? 33 c0 8d 54 24 1c 89 44 24 1c 89 44 24 20 89 44 24 24 89 44 24 28 89 44 24 2c } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_SmokeLoader_ASM_MTB_2{
	meta:
		description = "Trojan:Win32/SmokeLoader.ASM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {c6 05 61 b8 42 00 69 c6 05 62 b8 42 00 72 c6 05 67 b8 42 00 50 c6 05 6d b8 42 00 74 c6 05 6e b8 42 00 00 c6 05 63 b8 42 00 74 c6 05 6c b8 42 00 63 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_SmokeLoader_ASM_MTB_3{
	meta:
		description = "Trojan:Win32/SmokeLoader.ASM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {c7 04 24 e8 a5 42 00 57 a3 20 e9 42 00 ff d6 50 e8 ?? ?? ?? ?? c7 04 24 d4 a5 42 00 57 a3 24 e9 42 00 ff d6 50 e8 ?? ?? ?? ?? c7 04 24 b8 a5 42 00 57 a3 28 e9 42 00 ff d6 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}