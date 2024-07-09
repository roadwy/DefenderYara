
rule TrojanDropper_Win32_Barlaiy_A_dha{
	meta:
		description = "TrojanDropper:Win32/Barlaiy.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {99 b9 00 00 90 01 f7 f9 bf 00 00 20 03 2b fa } //1
		$a_03_1 = {68 00 6a 02 00 68 ?? ?? ?? ?? 56 e8 ?? ?? ?? ?? 8b 44 24 ?? 81 c6 00 6a 02 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}