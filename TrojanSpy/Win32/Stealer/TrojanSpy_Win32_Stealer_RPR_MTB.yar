
rule TrojanSpy_Win32_Stealer_RPR_MTB{
	meta:
		description = "TrojanSpy:Win32/Stealer.RPR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {39 d3 0f 8e ?? ff ff ff 90 09 35 00 [0-20] 8a 03 [0-10] 88 06 [0-20] 46 [0-20] 81 c3 02 00 00 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}