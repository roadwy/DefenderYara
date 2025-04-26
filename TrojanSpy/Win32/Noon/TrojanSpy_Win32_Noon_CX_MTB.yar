
rule TrojanSpy_Win32_Noon_CX_MTB{
	meta:
		description = "TrojanSpy:Win32/Noon.CX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {33 d2 8b c1 f7 f3 41 8a 44 15 f4 8b ?? ?? ?? ?? ?? 30 44 11 ff 3b 4c 37 fc 72 ?? 8b 4c 37 fc 68 ?? ?? ?? ?? 6a 40 51 52 ff 15 ?? ?? ?? ?? 8b ?? ?? ?? ?? ?? ff d0 6a 00 ff 15 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}