
rule Trojan_Win32_Zusy_ARA_MTB{
	meta:
		description = "Trojan:Win32/Zusy.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {89 c8 31 d2 f7 f6 8b 47 28 0f b6 04 10 30 04 0b 83 c1 01 39 cd 75 e9 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Zusy_ARA_MTB_2{
	meta:
		description = "Trojan:Win32/Zusy.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {b8 81 80 80 80 f7 e1 c1 ea 07 02 d1 30 91 90 01 04 41 81 f9 eb d5 06 00 72 e5 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}