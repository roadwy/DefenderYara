
rule Trojan_Win32_Zenpak_ASL_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.ASL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {f7 e1 c1 ea 08 69 c2 41 01 00 00 8b 4d 90 01 01 29 c1 89 c8 83 e8 01 89 4d 90 01 01 89 45 90 01 01 74 90 00 } //01 00 
		$a_01_1 = {83 f2 07 40 83 f2 02 29 d0 89 e0 50 } //00 00 
	condition:
		any of ($a_*)
 
}