
rule Backdoor_Win32_Mokes_GMP_MTB{
	meta:
		description = "Backdoor:Win32/Mokes.GMP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {0f be c9 0f bf d2 66 81 e2 e5 00 66 c1 d2 26 66 49 f7 eb 66 c1 e6 75 66 c1 e2 a8 66 83 c1 3e c1 c0 48 66 c1 d8 1c 66 81 e3 c9 01 66 33 ca 8b 45 d8 0f b7 c8 8b 45 d0 8b 40 1c 8d 04 88 8b 4d e0 8b 34 08 8d 4d e4 } //00 00 
	condition:
		any of ($a_*)
 
}