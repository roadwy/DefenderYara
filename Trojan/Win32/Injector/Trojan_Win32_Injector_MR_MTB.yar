
rule Trojan_Win32_Injector_MR_MTB{
	meta:
		description = "Trojan:Win32/Injector.MR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {47 00 71 00 4e 00 52 00 6d 00 61 00 76 00 61 00 6e 00 79 00 6a 00 38 00 43 00 4c 00 66 00 58 00 75 00 6a 00 68 00 34 00 4f 00 43 00 4b 00 4a 00 51 00 49 00 35 00 32 00 33 00 } //1 GqNRmavanyj8CLfXujh4OCKJQI523
		$a_01_1 = {6d 00 4c 00 30 00 50 00 5a 00 59 00 65 00 52 00 32 00 4a 00 46 00 4b 00 59 00 32 00 33 00 37 00 } //1 mL0PZYeR2JFKY237
		$a_00_2 = {4d 53 56 42 56 4d 36 30 2e 44 4c 4c } //1 MSVBVM60.DLL
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}
rule Trojan_Win32_Injector_MR_MTB_2{
	meta:
		description = "Trojan:Win32/Injector.MR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {0a 0a 02 17 8d ?? ?? ?? 01 25 16 1f ?? 9d 6f ?? ?? ?? 0a 0b 00 07 0c 16 0d 2b ?? 08 09 9a 13 ?? 00 06 11 ?? 1f ?? 28 ?? ?? ?? 0a d1 6f ?? ?? ?? 0a 26 00 09 17 58 0d 09 08 8e 69 32 } //1
		$a_02_1 = {06 0b 07 13 ?? 11 ?? 0d 09 2c ?? 09 72 ?? ?? ?? 70 28 ?? ?? ?? 0a 2d ?? 2b ?? 2b ?? 07 28 ?? ?? ?? 06 74 ?? ?? ?? 01 0c 08 28 ?? ?? ?? 06 00 2b } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}