
rule Trojan_Win32_Racealer_Y_MTB{
	meta:
		description = "Trojan:Win32/Racealer.Y!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {83 e8 1e a2 90 01 04 0f be 0d 90 01 04 83 e9 14 88 0d 90 01 04 0f be 15 90 01 04 83 ea 14 88 15 90 01 04 0f be 05 90 01 04 83 e8 0a a2 90 00 } //1
		$a_00_1 = {8b 4d e4 33 4d f0 89 4d e4 8b 55 ec 33 55 e4 89 55 ec } //1
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}