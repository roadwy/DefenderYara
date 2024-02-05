
rule Trojan_Win32_Racealer_C_MTB{
	meta:
		description = "Trojan:Win32/Racealer.C!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {01 45 fc b8 56 c4 08 00 01 45 } //01 00 
		$a_01_1 = {89 45 ec 8b 45 ec 03 45 d4 89 45 ec 8b 45 e4 33 45 f0 89 45 e4 8b 45 e4 33 45 ec 89 45 e4 8b 45 e4 29 45 d0 8b 45 d8 } //00 00 
	condition:
		any of ($a_*)
 
}