
rule TrojanSpy_Win32_Lokibot_V_MTB{
	meta:
		description = "TrojanSpy:Win32/Lokibot.V!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {b3 02 33 ff 90 02 06 8b c7 90 02 05 8a 90 90 90 01 04 32 d3 90 02 05 a1 90 01 04 03 c7 90 02 04 8b f0 90 02 06 8b c6 e8 90 01 04 90 02 05 47 81 ff 90 01 04 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}