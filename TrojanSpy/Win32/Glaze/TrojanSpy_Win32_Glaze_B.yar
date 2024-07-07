
rule TrojanSpy_Win32_Glaze_B{
	meta:
		description = "TrojanSpy:Win32/Glaze.B,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {66 8b 43 02 50 ff 15 90 01 02 00 10 66 3d 15 00 90 03 01 01 75 0f 90 02 05 ff 73 04 ff 15 90 01 02 00 10 80 a5 90 01 01 ff ff ff 00 6a 31 8b 90 01 01 59 33 c0 8d bd 90 01 01 ff ff ff f3 ab 66 ab aa 90 02 01 8d 85 90 01 01 ff ff ff 68 90 01 02 00 10 50 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}