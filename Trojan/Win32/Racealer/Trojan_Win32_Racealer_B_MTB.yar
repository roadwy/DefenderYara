
rule Trojan_Win32_Racealer_B_MTB{
	meta:
		description = "Trojan:Win32/Racealer.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {49 81 c9 00 ff ff ff 41 8a 89 ?? ?? ?? ?? 88 0d ?? ?? ?? ?? 0f b6 05 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 03 4d ec 0f be 11 33 d0 a1 ?? ?? ?? ?? 03 45 ec 88 10 e9 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Racealer_B_MTB_2{
	meta:
		description = "Trojan:Win32/Racealer.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {61 94 27 27 c7 45 ?? a9 f0 49 67 c7 85 ?? ?? ?? ?? 7a f3 78 2d c7 45 ?? 41 7e 29 56 c7 45 ?? ca 3f 84 06 c7 45 ?? 11 60 50 25 c7 45 ?? 4d 35 a2 53 c7 45 ?? cd 54 42 71 c7 45 ?? f9 b6 59 13 } //1
		$a_02_1 = {46 9e c8 16 c7 45 ?? e7 04 23 11 c7 85 ?? ?? ?? ?? bb d2 3f 34 c7 85 ?? ?? ?? ?? 34 f5 a4 76 c7 45 ?? 3d fc d3 75 c7 45 ?? 97 1e 0c 09 c7 45 ?? 10 00 02 7e c7 85 ?? ?? ?? ?? e5 6f f8 60 c7 45 ?? 4c 68 65 4e } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}