
rule TrojanSpy_Win32_Stealer_RPR_MTB{
	meta:
		description = "TrojanSpy:Win32/Stealer.RPR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {39 d3 0f 8e 90 01 01 ff ff ff 90 09 35 00 90 02 20 8a 03 90 02 10 88 06 90 02 20 46 90 02 20 81 c3 02 00 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}