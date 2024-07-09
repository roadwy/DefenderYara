
rule Backdoor_Win32_Drixed_I{
	meta:
		description = "Backdoor:Win32/Drixed.I,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {b8 37 00 00 00 e8 ?? ?? ?? ?? 89 44 ?? ?? b8 87 00 00 00 e8 ?? ?? ?? ?? 89 44 ?? ?? b8 77 00 00 00 e8 } //1
		$a_03_1 = {b8 83 00 00 00 89 8c ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? 6a 40 68 00 30 00 00 68 60 28 00 00 6a 00 ff d0 } //1
		$a_03_2 = {6a 36 58 e8 ?? ?? ?? ?? 6a 00 ff 33 ff d0 eb } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}