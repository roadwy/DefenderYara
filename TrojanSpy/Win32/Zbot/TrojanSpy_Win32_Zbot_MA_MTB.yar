
rule TrojanSpy_Win32_Zbot_MA_MTB{
	meta:
		description = "TrojanSpy:Win32/Zbot.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {b3 50 fc 44 8b 85 90 01 04 ed 3c 3a 4f ad 33 99 90 01 04 0c 00 aa 00 60 d3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}