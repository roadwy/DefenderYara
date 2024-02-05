
rule Trojan_Win32_Zusy_GPAD_MTB{
	meta:
		description = "Trojan:Win32/Zusy.GPAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 04 00 "
		
	strings :
		$a_03_0 = {0f b6 0e 03 c8 0f b6 c1 8b 4c 24 10 8a 84 04 14 01 00 00 30 85 90 01 04 45 81 fd 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}