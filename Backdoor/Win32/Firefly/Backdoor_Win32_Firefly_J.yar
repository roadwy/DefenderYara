
rule Backdoor_Win32_Firefly_J{
	meta:
		description = "Backdoor:Win32/Firefly.J,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 05 00 00 "
		
	strings :
		$a_00_0 = {46 69 72 65 46 6c 79 } //1 FireFly
		$a_00_1 = {53 65 72 70 65 6e 74 2e 64 6c 6c } //1 Serpent.dll
		$a_00_2 = {68 7a 78 68 7a 78 31 32 33 } //1 hzxhzx123
		$a_02_3 = {64 ff 30 64 89 20 6a 00 6a 00 6a 00 6a 00 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 89 45 } //10
		$a_02_4 = {6a 01 8d 44 24 10 50 e8 ?? ?? ?? ?? 6a 00 6a 00 6a ff 8d 44 24 18 50 e8 ?? ?? ?? ?? c7 04 24 0c 00 00 00 8d 44 24 0c 89 44 24 04 c7 44 24 08 ff ff ff ff 68 ?? ?? ?? ?? 6a ff 6a 06 } //10
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_02_3  & 1)*10+(#a_02_4  & 1)*10) >=22
 
}