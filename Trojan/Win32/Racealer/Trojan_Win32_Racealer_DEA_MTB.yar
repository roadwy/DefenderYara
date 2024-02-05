
rule Trojan_Win32_Racealer_DEA_MTB{
	meta:
		description = "Trojan:Win32/Racealer.DEA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 04 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b d0 d3 e2 8b c8 c1 e9 05 03 8d 90 01 01 fd ff ff 03 95 90 01 01 fd ff ff 03 f8 33 d1 33 d7 89 95 90 01 01 fd ff ff 89 35 90 00 } //01 00 
		$a_81_1 = {73 6c 6f 6b 61 64 6e 69 61 73 64 62 66 69 61 73 64 } //01 00 
		$a_81_2 = {66 61 69 75 73 64 66 69 61 73 64 68 67 6f 73 64 66 6a 67 6f 73 } //01 00 
		$a_81_3 = {64 67 6f 73 64 66 6a 67 6f 69 73 64 6f 66 67 6d } //00 00 
	condition:
		any of ($a_*)
 
}