
rule Trojan_Win32_Redline_AL_MTB{
	meta:
		description = "Trojan:Win32/Redline.AL!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {5f 89 70 04 5e 5d 89 10 5b } //1
		$a_01_1 = {51 c7 04 24 00 00 00 00 8b 44 24 0c 89 04 24 8b 44 24 08 31 04 24 8b 04 24 89 01 59 c2 08 00 } //1
		$a_01_2 = {61 63 69 6e 61 34 39 20 76 75 2e 70 64 62 } //1 acina49 vu.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}