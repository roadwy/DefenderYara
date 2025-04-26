
rule TrojanDropper_Win32_Oficla_G{
	meta:
		description = "TrojanDropper:Win32/Oficla.G,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 "
		
	strings :
		$a_03_0 = {ff 0f 0f 86 ?? ?? ?? ?? 83 bd ?? ?? ff ff 53 0f 86 ?? ?? ?? ?? 0f be 90 09 05 00 83 bd ?? ?? ff } //3
		$a_03_1 = {83 c7 01 83 ff (28|32) 75 } //1
		$a_03_2 = {c7 04 24 04 01 00 00 90 09 04 00 89 ?? 24 04 } //3
		$a_03_3 = {0f be 81 00 30 40 00 83 e0 0f 39 ?? 75 } //1
		$a_03_4 = {ff ff ff 03 00 00 0f 86 90 09 04 00 81 bd ?? (e9|ea) } //1
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*1+(#a_03_2  & 1)*3+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1) >=7
 
}