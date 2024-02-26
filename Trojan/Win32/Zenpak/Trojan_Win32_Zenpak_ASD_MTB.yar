
rule Trojan_Win32_Zenpak_ASD_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.ASD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {f7 e1 c1 ea 04 6b c2 90 01 01 8b 4e 90 01 01 29 c1 89 c8 83 e8 02 89 4e 90 01 01 89 46 08 0f 84 90 00 } //01 00 
		$a_03_1 = {31 d0 31 c2 4a 48 8d 05 90 01 04 01 30 b9 02 00 00 00 e2 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}