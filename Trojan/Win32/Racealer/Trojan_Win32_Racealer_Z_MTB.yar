
rule Trojan_Win32_Racealer_Z_MTB{
	meta:
		description = "Trojan:Win32/Racealer.Z!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {c1 e0 04 89 01 c3 31 08 c3 90 02 20 33 44 24 08 c2 08 00 81 00 fe 36 ef c6 c3 90 00 } //1
		$a_03_1 = {8b d6 d3 ea 03 c6 90 02 20 31 45 f8 89 45 ec 90 02 20 03 ca c1 ea 05 89 55 f8 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}