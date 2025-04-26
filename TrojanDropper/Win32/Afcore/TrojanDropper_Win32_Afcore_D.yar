
rule TrojanDropper_Win32_Afcore_D{
	meta:
		description = "TrojanDropper:Win32/Afcore.D,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 04 00 00 "
		
	strings :
		$a_00_0 = {b8 00 00 00 80 50 50 56 56 68 00 00 df 00 57 57 56 } //1
		$a_02_1 = {b8 00 00 00 80 50 50 56 56 68 00 00 df 00 68 ?? ?? ?? 00 68 ?? ?? ?? 00 56 ff 15 } //1
		$a_02_2 = {b8 00 00 00 80 50 50 56 56 68 00 00 df 00 ff ?? ?? ff ?? ?? 56 ff 15 } //1
		$a_02_3 = {83 ec 40 48 74 ?? 48 74 ?? 83 e8 0d 74 ?? 2d f1 03 00 00 74 } //10
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1+(#a_02_3  & 1)*10) >=11
 
}