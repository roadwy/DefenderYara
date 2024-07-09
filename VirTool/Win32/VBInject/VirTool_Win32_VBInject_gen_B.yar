
rule VirTool_Win32_VBInject_gen_B{
	meta:
		description = "VirTool:Win32/VBInject.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0b 00 07 00 00 "
		
	strings :
		$a_01_0 = {45 41 44 57 52 49 50 72 6f 6a 65 63 74 31 00 45 58 45 43 55 54 45 } //5 䅅坄䥒牐橯捥ㅴ䔀䕘啃䕔
		$a_01_1 = {6d 6f 64 49 6e 6a 65 63 74 } //5 modInject
		$a_01_2 = {6d 6f 64 43 72 79 70 74 } //2 modCrypt
		$a_01_3 = {6d 6f 64 50 72 6f 74 65 63 74 } //2 modProtect
		$a_01_4 = {6d 6f 64 4d 61 69 6e } //2 modMain
		$a_00_5 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 WriteProcessMemory
		$a_03_6 = {f5 04 00 00 00 f5 00 30 00 00 6c ?? ?? 6c ?? ?? 6c ?? ?? 5e ?? ?? ?? ?? 71 ?? ?? 3c 6c ?? ?? 71 ?? ?? 6c ?? ?? f5 00 00 00 00 c7 } //9
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_00_5  & 1)*1+(#a_03_6  & 1)*9) >=11
 
}