
rule Trojan_Win32_GhostRAT_A_MTB{
	meta:
		description = "Trojan:Win32/GhostRAT.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {0f b6 00 8b 55 f4 31 d0 83 f0 90 01 01 89 c2 8b 45 90 01 01 05 20 90 01 03 88 10 8b 45 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}