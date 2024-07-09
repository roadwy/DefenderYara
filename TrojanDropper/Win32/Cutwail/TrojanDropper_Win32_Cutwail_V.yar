
rule TrojanDropper_Win32_Cutwail_V{
	meta:
		description = "TrojanDropper:Win32/Cutwail.V,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 04 00 00 "
		
	strings :
		$a_02_0 = {83 f0 06 f7 d0 8d 75 f4 8b 3e 23 f8 89 3e 90 09 0f 00 ff 15 ?? ?? 40 00 83 c4 1c ff 15 ?? ?? 40 00 } //1
		$a_02_1 = {8b 4d 08 8b 55 0c 80 01 ?? 41 4a 75 f9 83 05 ?? ?? ?? ?? ?? e8 ?? ?? 00 00 83 f0 06 } //1
		$a_02_2 = {56 53 8d 05 ?? ?? 40 00 25 00 00 ff ff 05 00 70 00 00 8d b0 88 00 00 00 8b 48 74 89 0d } //1
		$a_00_3 = {6a 40 b9 0b 00 00 00 8b c1 05 00 30 00 00 50 29 0c 24 ff 73 50 50 8d } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1+(#a_00_3  & 1)*1) >=1
 
}