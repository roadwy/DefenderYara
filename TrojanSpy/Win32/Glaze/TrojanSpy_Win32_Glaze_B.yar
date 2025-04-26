
rule TrojanSpy_Win32_Glaze_B{
	meta:
		description = "TrojanSpy:Win32/Glaze.B,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {66 8b 43 02 50 ff 15 ?? ?? 00 10 66 3d 15 00 (75|0f) [0-05] ff 73 04 ff 15 ?? ?? 00 10 80 a5 ?? ff ff ff 00 6a 31 8b ?? 59 33 c0 8d bd ?? ff ff ff f3 ab 66 ab aa [0-01] 8d 85 ?? ff ff ff 68 ?? ?? 00 10 50 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}