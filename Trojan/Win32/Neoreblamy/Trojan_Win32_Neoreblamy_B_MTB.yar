
rule Trojan_Win32_Neoreblamy_B_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {d3 e0 33 45 90 01 01 99 89 45 90 00 } //02 00 
		$a_01_1 = {8b 06 85 c0 0f 99 c2 8b 0f 8b 06 2b ca 33 d2 3b c8 8b 06 } //00 00 
	condition:
		any of ($a_*)
 
}