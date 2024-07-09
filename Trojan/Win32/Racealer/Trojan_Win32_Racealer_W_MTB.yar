
rule Trojan_Win32_Racealer_W_MTB{
	meta:
		description = "Trojan:Win32/Racealer.W!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {c1 e0 04 89 01 c3 [0-30] 31 06 c9 c2 04 00 33 44 24 04 c2 04 00 81 00 fe 36 ef c6 c3 01 08 c3 } //1
		$a_00_1 = {89 55 fc b8 3b 2d 0b 00 01 45 fc 8b 45 fc 8a 04 08 88 04 31 41 3b 0d } //1
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}