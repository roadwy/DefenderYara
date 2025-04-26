
rule TrojanDropper_Win32_Rortiem_A{
	meta:
		description = "TrojanDropper:Win32/Rortiem.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {74 17 8d 45 ?? 50 ff 55 ?? 3d 61 00 00 c0 74 09 c7 45 ?? 01 00 00 00 eb ?? 68 3f 00 0f 00 } //1
		$a_03_1 = {68 40 02 00 00 50 6a 03 6a 0b ff 75 ?? ff 15 ?? ?? ?? ?? 85 c0 75 0d ff 15 ?? ?? ?? ?? 3d ea 00 00 00 75 ?? 39 75 ?? 89 75 ?? 7e ?? 8b 4d 08 8d 04 9b c1 e0 05 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}