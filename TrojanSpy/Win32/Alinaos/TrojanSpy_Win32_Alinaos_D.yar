
rule TrojanSpy_Win32_Alinaos_D{
	meta:
		description = "TrojanSpy:Win32/Alinaos.D,SIGNATURE_TYPE_PEHSTR_EXT,06 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {41 6c 69 6e 61 20 76 90 0f 01 00 2e 90 0f 01 00 } //2
		$a_03_1 = {53 57 6a 00 6a 00 6a 00 6a 01 68 ?? ?? ?? ?? 89 45 ?? 89 4d ?? 8b fa c7 45 ?? 00 00 00 00 ff 15 ?? ?? ?? ?? 8b d8 89 5d ?? 85 db 0f 84 ?? ?? ?? ?? 83 fb ff 0f 84 ?? ?? ?? ?? 56 6a 00 6a 00 6a 03 6a 00 6a 00 6a 50 68 ?? ?? ?? ?? 53 ff 15 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}