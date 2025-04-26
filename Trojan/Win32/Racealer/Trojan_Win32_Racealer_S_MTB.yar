
rule Trojan_Win32_Racealer_S_MTB{
	meta:
		description = "Trojan:Win32/Racealer.S!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 c0 c2 04 00 c1 e0 04 89 01 c3 [0-25] 8b 44 24 04 31 06 c2 04 00 33 44 24 04 c2 04 00 81 00 fe 36 ef c6 c3 01 08 c3 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}