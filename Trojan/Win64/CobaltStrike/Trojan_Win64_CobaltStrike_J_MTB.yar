
rule Trojan_Win64_CobaltStrike_J_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.J!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {44 8b c0 48 8d 5b 90 01 01 b8 90 01 04 41 f7 e8 c1 fa 90 01 01 8b ca c1 e9 90 01 01 03 d1 69 ca 90 01 04 44 2b c1 41 fe c0 44 32 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}