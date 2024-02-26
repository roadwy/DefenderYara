
rule Trojan_Win32_CobaltStrike_TE_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.TE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {0f af da 8b d3 c1 ea 10 88 14 01 8b d3 ff 47 90 01 01 8b 87 90 01 04 2d 90 01 04 c1 ea 08 31 05 54 7a 4d 00 8b 47 6c 8b 8f 90 01 04 88 14 01 ff 47 90 01 01 8b 4f 90 01 01 a1 90 01 04 88 1c 01 ff 47 6c 81 fe 90 01 04 0f 8c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}