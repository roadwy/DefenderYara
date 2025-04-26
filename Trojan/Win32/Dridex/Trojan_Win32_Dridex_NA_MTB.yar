
rule Trojan_Win32_Dridex_NA_MTB{
	meta:
		description = "Trojan:Win32/Dridex.NA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_81_0 = {30 74 36 2d 2b 43 2a 50 64 32 2b 57 6b 21 65 2b 2d 2e 70 64 62 } //10 0t6-+C*Pd2+Wk!e+-.pdb
	condition:
		((#a_81_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Dridex_NA_MTB_2{
	meta:
		description = "Trojan:Win32/Dridex.NA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {89 08 5d c3 90 0a 25 00 33 [0-05] c7 05 [0-08] 01 15 [0-04] a1 [0-04] 8b } //1
		$a_02_1 = {83 c2 01 89 [0-05] eb 90 09 24 00 ff [0-05] 03 [0-05] 8b [0-05] 8b [0-05] 8a [0-03] 88 [0-03] 8b 15 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}