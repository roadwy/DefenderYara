
rule Trojan_Win32_Predator_BS_MTB{
	meta:
		description = "Trojan:Win32/Predator.BS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {8b d7 8b 45 e8 83 65 ec 00 03 c7 d3 ea 03 55 c4 33 d0 33 d6 8b 75 d0 2b f2 89 75 d0 c1 e3 0b } //1
		$a_02_1 = {8b 4d d8 8b d6 d3 ea 8b 4d e8 03 55 bc 8d 04 31 33 d8 81 3d 90 01 04 c1 10 00 00 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}