
rule Trojan_Win32_Racealer_X_MTB{
	meta:
		description = "Trojan:Win32/Racealer.X!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {83 e8 1e a2 90 01 04 0f be 0d 90 01 04 83 e9 14 88 0d 90 01 04 0f be 15 90 01 04 83 ea 14 88 15 90 01 04 0f be 05 90 01 04 83 e8 0a a2 90 00 } //01 00 
		$a_03_1 = {ec 08 c6 05 90 01 04 6c c6 05 90 01 04 88 c6 05 90 01 04 56 c6 05 90 01 04 61 c6 05 90 01 04 74 c6 05 90 01 04 6f c6 05 90 01 04 92 90 02 10 c7 45 f8 40 00 00 00 c6 05 90 01 04 72 c6 05 90 01 04 7f c6 05 90 01 04 65 c6 05 90 01 04 50 c6 05 90 01 04 00 c6 05 90 01 04 86 c6 05 90 01 04 63 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}