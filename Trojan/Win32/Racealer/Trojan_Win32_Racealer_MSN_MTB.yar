
rule Trojan_Win32_Racealer_MSN_MTB{
	meta:
		description = "Trojan:Win32/Racealer.MSN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {33 d2 8b c1 f7 75 08 81 3d 90 01 04 bc 09 00 00 8b fa 90 00 } //01 00 
		$a_02_1 = {81 e2 ff 00 00 00 0f b6 92 90 01 04 30 14 37 83 ee 01 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}