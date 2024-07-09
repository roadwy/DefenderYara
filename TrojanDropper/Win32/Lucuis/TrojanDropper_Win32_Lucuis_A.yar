
rule TrojanDropper_Win32_Lucuis_A{
	meta:
		description = "TrojanDropper:Win32/Lucuis.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {37 38 39 65 72 69 63 30 31 32 } //1 789eric012
		$a_03_1 = {8b 44 24 0c 56 8d 70 3f 8b 44 24 08 83 e6 c0 85 c0 0f 84 ?? ?? 00 00 8b 44 24 0c 85 c0 0f 84 ?? ?? 00 00 8b 44 24 14 85 c0 (0f 84 ?? ?? 00 00 74|?? 85 f6 74) ?? 8b 4c 24 18 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}