
rule Trojan_Win32_Stealerc_GPD_MTB{
	meta:
		description = "Trojan:Win32/Stealerc.GPD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 04 00 "
		
	strings :
		$a_03_0 = {0f b6 0f 8b 74 24 90 01 01 03 c8 0f b6 c1 8a 84 04 90 01 02 00 00 30 85 90 01 04 45 81 fd 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}