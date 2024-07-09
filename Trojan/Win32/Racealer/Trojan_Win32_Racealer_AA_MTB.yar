
rule Trojan_Win32_Racealer_AA_MTB{
	meta:
		description = "Trojan:Win32/Racealer.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {c1 e0 04 89 01 c3 31 08 c3 81 3d ?? ?? ?? ?? e6 01 00 00 [0-10] 8b 44 24 04 33 44 24 08 c2 08 00 81 00 12 37 ef c6 c3 } //1
		$a_03_1 = {8b d6 d3 ea 03 c6 50 [0-20] 31 45 f4 2b 7d f4 [0-1c] 8b c7 c1 e8 05 03 cf } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}