
rule Trojan_Win32_Fragtor_B_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f 29 44 24 60 0f 29 44 24 70 8b 91 90 01 04 33 54 08 04 89 54 0c 64 83 c1 04 83 f9 20 72 ea 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}