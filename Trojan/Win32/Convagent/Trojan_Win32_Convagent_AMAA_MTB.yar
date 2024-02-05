
rule Trojan_Win32_Convagent_AMAA_MTB{
	meta:
		description = "Trojan:Win32/Convagent.AMAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {33 eb 33 e8 2b f5 8b d6 c1 e2 04 89 54 24 90 01 01 8b 44 24 90 01 01 01 44 24 90 00 } //05 00 
		$a_03_1 = {33 d3 31 54 24 14 c7 05 90 01 08 8b 44 24 14 29 44 24 18 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}