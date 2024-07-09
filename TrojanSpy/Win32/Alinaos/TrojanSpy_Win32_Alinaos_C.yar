
rule TrojanSpy_Win32_Alinaos_C{
	meta:
		description = "TrojanSpy:Win32/Alinaos.C,SIGNATURE_TYPE_PEHSTR_EXT,06 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {41 6c 69 6e 61 20 76 90 0f 01 00 2e 90 0f 01 00 } //2
		$a_03_1 = {56 56 56 6a 01 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 8b f8 89 7d ?? 3b fe 0f 84 ?? ?? ?? ?? 83 ff ff 0f 84 ?? ?? ?? ?? 56 56 6a 03 56 56 6a 50 68 ?? ?? ?? ?? 57 ff 15 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}