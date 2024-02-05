
rule Trojan_Win32_Racealer_DE_MTB{
	meta:
		description = "Trojan:Win32/Racealer.DE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {89 18 6a 00 e8 90 01 04 8b 5d c8 03 5d a0 2b d8 6a 00 e8 90 01 04 03 d8 8b 45 d8 31 18 83 45 ec 04 6a 00 e8 90 01 04 bb 04 00 00 00 2b d8 6a 00 e8 90 01 04 03 d8 01 5d d8 8b 45 ec 3b 45 d4 0f 82 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}