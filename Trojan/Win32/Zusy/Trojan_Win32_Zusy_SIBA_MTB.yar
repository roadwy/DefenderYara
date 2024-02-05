
rule Trojan_Win32_Zusy_SIBA_MTB{
	meta:
		description = "Trojan:Win32/Zusy.SIBA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b f8 8b f1 2b d2 90 02 10 8a 0f 8a 06 46 90 18 47 80 7d 08 90 01 01 90 18 88 4d 90 01 01 90 18 0f 84 90 01 04 8a ca bb 90 01 04 90 02 10 d3 c3 8a 4d 90 1b 04 90 02 10 02 da 90 02 10 32 c3 90 18 42 90 02 10 84 c0 0f 84 90 01 04 3a c1 0f 84 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}