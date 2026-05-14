
rule Trojan_Win32_Zusy_LMZ_MTB{
	meta:
		description = "Trojan:Win32/Zusy.LMZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_01_0 = {66 33 44 4c 34 66 89 84 4c f0 00 00 00 41 83 f9 0b 72 e1 8d 84 24 f0 00 00 00 e9 } //20
		$a_01_1 = {c7 44 24 4c 61 00 68 00 c7 44 24 50 8c 00 1a 00 33 c9 c7 44 24 54 70 00 65 00 c7 44 24 58 c9 00 49 00 c7 44 24 5c 2e 00 68 00 c7 44 24 60 96 00 17 00 66 89 44 24 64 } //10
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*10) >=30
 
}