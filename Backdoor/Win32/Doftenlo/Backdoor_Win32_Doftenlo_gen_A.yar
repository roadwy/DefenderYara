
rule Backdoor_Win32_Doftenlo_gen_A{
	meta:
		description = "Backdoor:Win32/Doftenlo.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {33 c0 8a 88 ?? ?? ?? ?? 30 0c 37 40 83 f8 09 72 f1 83 3d ?? ?? ?? ?? 00 74 03 f6 14 37 56 47 e8 ?? ?? ?? ?? 3b f8 59 72 d7 } //1
		$a_03_1 = {68 0c 17 00 00 57 8d 04 40 ff 34 85 ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 c4 0c 85 c0 74 af } //1
		$a_01_2 = {66 81 78 0e 28 0a 75 29 0f b7 40 0c 3d 84 08 00 00 74 19 3d 4c 0b 00 00 74 0d } //1
		$a_01_3 = {25 73 20 28 55 70 74 69 6d 65 3a 20 25 64 64 29 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}