
rule Trojan_Win32_Citadel_A_MTB{
	meta:
		description = "Trojan:Win32/Citadel.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {33 c1 33 d2 b9 90 01 04 f7 f1 8b cb 2b c8 8b 45 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}