
rule TrojanSpy_Win32_Glaze_A{
	meta:
		description = "TrojanSpy:Win32/Glaze.A,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {6a 02 5f c6 06 4d 39 7d f8 c6 46 01 5a 76 23 89 5d fc 29 75 fc 8b c7 bb ff 00 00 00 99 f7 fb 8b 45 fc 8d 0c 37 8a 04 08 32 c2 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}