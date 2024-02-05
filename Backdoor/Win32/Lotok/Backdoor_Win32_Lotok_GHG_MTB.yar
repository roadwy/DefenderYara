
rule Backdoor_Win32_Lotok_GHG_MTB{
	meta:
		description = "Backdoor:Win32/Lotok.GHG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {c6 45 e4 55 c6 45 e5 52 c6 45 e6 4c c6 45 e7 44 c6 45 e8 6f c6 45 e9 77 c6 45 ea 6e c6 45 eb 6c c6 45 ec 6f c6 45 ed 61 c6 45 ee 64 c6 45 ef 54 c6 45 f0 6f c6 45 f1 46 c6 45 f2 69 c6 45 f3 6c c6 45 f4 65 c6 45 f5 41 c6 45 f6 00 8d 45 e4 50 8b 4d d8 51 ff 15 } //00 00 
	condition:
		any of ($a_*)
 
}