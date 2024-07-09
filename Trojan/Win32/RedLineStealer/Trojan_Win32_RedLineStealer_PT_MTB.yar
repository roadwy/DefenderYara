
rule Trojan_Win32_RedLineStealer_PT_MTB{
	meta:
		description = "Trojan:Win32/RedLineStealer.PT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {c1 e8 05 c7 05 ?? ?? ?? ?? 19 36 6b ff 89 45 08 8b 45 e4 01 45 08 8b 45 08 33 45 0c 33 c8 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_RedLineStealer_PT_MTB_2{
	meta:
		description = "Trojan:Win32/RedLineStealer.PT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 44 24 18 89 44 24 1c 8b 44 24 2c 01 44 24 1c 8b 44 24 18 c1 e8 05 89 44 24 14 8b 4c 24 10 33 4c 24 1c 8b 44 24 14 [0-10] 33 c1 } //1
		$a_03_1 = {c1 e8 05 c7 05 ?? ?? ?? ?? 19 36 6b ff 89 45 08 8b 45 e4 01 45 08 8b 45 08 33 45 0c 81 45 f8 47 86 c8 61 33 c1 2b f0 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}