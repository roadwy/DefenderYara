
rule Backdoor_Win32_Padodor_GMC_MTB{
	meta:
		description = "Backdoor:Win32/Padodor.GMC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {54 48 45 4e 20 41 20 4e 59 20 49 4d 50 4c 49 45 44 20 57 41 52 52 41 20 4e 54 49 45 53 } //01 00  THEN A NY IMPLIED WARRA NTIES
		$a_01_1 = {66 61 20 33 72 6b 2a 33 72 56 } //01 00  fa 3rk*3rV
		$a_01_2 = {66 33 72 6b 4b 68 } //00 00  f3rkKh
	condition:
		any of ($a_*)
 
}