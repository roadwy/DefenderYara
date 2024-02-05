
rule Trojan_Win32_Racealer_A_MTB{
	meta:
		description = "Trojan:Win32/Racealer.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {83 f0 40 83 f0 06 8b f4 50 68 00 30 00 00 0f b7 0d 90 01 04 81 f1 b9 a6 98 00 83 f1 06 51 6a 00 8b fc ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}