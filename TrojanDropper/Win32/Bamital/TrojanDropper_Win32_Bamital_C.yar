
rule TrojanDropper_Win32_Bamital_C{
	meta:
		description = "TrojanDropper:Win32/Bamital.C,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {bf 20 83 b8 ed 33 d2 8a 16 32 d0 d1 ea 73 02 33 d7 41 80 e1 07 75 f4 } //1
		$a_01_1 = {83 c6 01 e2 f8 64 8b 15 30 00 00 00 8b 52 0c 8b 52 0c 8b 52 18 81 7a 20 bb 07 00 00 } //1
		$a_03_2 = {8b 4d 08 89 0d ?? ?? ?? ?? b9 ?? ?? ?? ?? 89 0d ?? ?? ?? ?? 8b d0 68 ?? ?? ?? ?? 6a 01 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6a 00 6a 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}