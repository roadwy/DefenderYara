
rule Trojan_Win32_Rozena_XI_MTB{
	meta:
		description = "Trojan:Win32/Rozena.XI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {89 f0 f7 e5 d1 ea 83 e2 90 01 01 8d 04 52 89 f2 29 c2 0f b6 92 90 01 04 30 14 37 f7 d8 0f b6 84 06 90 01 04 30 44 37 90 01 01 83 c6 90 01 01 39 f3 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}