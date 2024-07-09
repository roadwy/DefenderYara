
rule TrojanSpy_Win32_Weecnaw_G_MTB{
	meta:
		description = "TrojanSpy:Win32/Weecnaw.G!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {c6 45 eb 02 6a 00 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8b 8d a0 e7 ff ff e8 4c f7 fa ff 6a 04 } //1
		$a_00_1 = {3a 29 55 51 00 ae 11 1f 22 ad 78 0e 97 e3 f5 80 e0 58 88 5a } //1
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}