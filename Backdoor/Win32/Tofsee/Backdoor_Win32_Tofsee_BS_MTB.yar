
rule Backdoor_Win32_Tofsee_BS_MTB{
	meta:
		description = "Backdoor:Win32/Tofsee.BS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_02_0 = {6a 00 6a 00 6a 00 6a 00 6a 00 ff 15 ?? ?? ?? ?? 6a 00 ff 15 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 4d 08 30 04 0e 46 3b 75 0c 7c ?? 5f 5e 5b 8b e5 5d c2 08 00 } //2
		$a_02_1 = {8b c7 c1 e8 05 03 44 24 38 03 d7 33 ca 81 3d ?? ?? ?? ?? 72 07 00 00 89 1d ?? ?? ?? ?? 89 1d ?? ?? ?? ?? 75 } //1
		$a_02_2 = {8b fd d3 e7 8b f5 c1 ee 05 03 74 24 28 03 7c 24 2c 03 c5 33 f8 81 3d ?? ?? ?? ?? b4 11 00 00 75 } //1
	condition:
		((#a_02_0  & 1)*2+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1) >=2
 
}