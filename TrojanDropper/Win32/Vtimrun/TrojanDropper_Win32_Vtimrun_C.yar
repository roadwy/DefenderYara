
rule TrojanDropper_Win32_Vtimrun_C{
	meta:
		description = "TrojanDropper:Win32/Vtimrun.C,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {40 00 50 e8 ?? ?? 00 00 8d 85 ?? ?? ff ff c6 ?? ?? 44 50 8d 85 ?? ?? ff ff 50 c6 ?? ?? 6c c6 ?? ?? 6c c6 ?? ?? 43 c6 ?? ?? 61 c6 ?? ?? 63 c6 ?? ?? 68 c6 ?? ?? 65 c6 ?? ?? 5c 88 ?? ?? e8 } //1
		$a_02_1 = {40 65 63 68 6f [0-05] 6f 66 66 0d 0a 3a 74 72 79 [0-07] 64 65 6c } //1
	condition:
		((#a_03_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}