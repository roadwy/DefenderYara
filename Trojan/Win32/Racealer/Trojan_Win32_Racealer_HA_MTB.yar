
rule Trojan_Win32_Racealer_HA_MTB{
	meta:
		description = "Trojan:Win32/Racealer.HA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {33 74 24 0c 8b 44 24 08 89 30 5e c2 08 00 33 44 24 04 c2 04 00 81 00 a4 36 ef c6 c3 01 08 c3 } //1
		$a_03_1 = {89 55 fc b8 3b 2d 0b 00 01 45 fc 8b 45 fc 8a 04 08 88 04 31 41 3b 0d 90 01 04 72 e3 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}