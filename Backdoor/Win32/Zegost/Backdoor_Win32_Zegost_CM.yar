
rule Backdoor_Win32_Zegost_CM{
	meta:
		description = "Backdoor:Win32/Zegost.CM,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {c6 45 f0 86 c6 45 ec 59 } //01 00 
		$a_01_1 = {0f be 45 f0 2b d0 8b 4d f4 03 4d fc 88 11 8b 55 f4 03 55 fc 0f be 02 0f be 4d ec 33 c1 } //01 00 
		$a_01_2 = {c6 45 f0 43 c6 45 f1 6f c6 45 f2 6e c6 45 f3 6e c6 45 f4 65 c6 45 f5 63 c6 45 f6 74 } //00 00 
	condition:
		any of ($a_*)
 
}