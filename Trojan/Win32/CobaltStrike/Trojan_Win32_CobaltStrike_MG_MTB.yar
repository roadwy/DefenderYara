
rule Trojan_Win32_CobaltStrike_MG_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.MG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {c1 ea 18 01 86 c0 00 00 00 8b 46 50 8b 8e a0 00 00 00 88 14 01 8b cb ff 46 50 a1 90 01 04 8b 56 50 c1 e9 10 8b 80 a0 00 00 00 88 0c 02 8b d3 ff 46 50 a1 90 01 04 c1 ea 08 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}