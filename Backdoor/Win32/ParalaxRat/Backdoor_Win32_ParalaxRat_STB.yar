
rule Backdoor_Win32_ParalaxRat_STB{
	meta:
		description = "Backdoor:Win32/ParalaxRat.STB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_03_0 = {8b c1 83 e0 1f 8a 44 05 dc 30 81 ?? ?? ?? ?? 41 81 f9 00 60 00 00 72 e8 b8 ?? ?? ?? ?? ff d0 } //5
		$a_03_1 = {b0 36 00 00 7c ?? 42 81 fa 80 fc 0a 00 7c ?? c7 45 dc } //1
		$a_03_2 = {6a 40 68 00 60 00 00 68 ?? ?? ?? ?? ff 55 f4 c7 45 f0 ?? ?? ?? ?? ff 65 f0 } //1
		$a_03_3 = {3d 40 1f 00 00 7c ee 42 81 fa b0 8f 06 00 7c e3 c7 45 d0 [0-0a] c7 45 d4 ?? ?? ?? ?? c7 45 d8 ?? ?? ?? ?? c7 45 dc } //2
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*2) >=6
 
}