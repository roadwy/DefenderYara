
rule Trojan_Win32_Zusy_AA_MTB{
	meta:
		description = "Trojan:Win32/Zusy.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_02_0 = {53 8b da c1 eb 90 01 01 8b 07 69 f6 90 01 04 69 c0 90 01 04 8b c8 c1 e9 90 01 01 33 c8 69 c9 95 e9 d1 5b 33 f1 83 ea 90 01 01 83 c7 90 01 01 4b 75 da 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}