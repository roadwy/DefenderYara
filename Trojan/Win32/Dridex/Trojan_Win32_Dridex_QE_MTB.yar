
rule Trojan_Win32_Dridex_QE_MTB{
	meta:
		description = "Trojan:Win32/Dridex.QE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 02 00 00 0a 00 "
		
	strings :
		$a_00_0 = {c6 44 24 4f f9 8a 5c 24 7f 80 c3 e3 88 5c 24 7f 8a 18 89 4c 24 78 0f b6 c3 66 8b 74 24 74 83 f8 6a 89 4c 24 34 66 89 74 24 32 } //03 00 
		$a_81_1 = {46 46 50 47 47 4c 42 4d 2e 70 64 62 } //00 00  FFPGGLBM.pdb
	condition:
		any of ($a_*)
 
}