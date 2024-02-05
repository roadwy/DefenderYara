
rule TrojanSpy_Win32_Keatep_A{
	meta:
		description = "TrojanSpy:Win32/Keatep.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {74 25 83 bd 90 01 02 ff ff 15 74 1c 81 bd 90 01 02 ff ff 49 08 00 00 74 10 81 bd 90 01 02 ff ff 49 08 00 00 0f 85 90 01 02 00 00 8b 90 01 02 0f be 90 01 01 83 90 01 01 55 74 0b 8b 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}