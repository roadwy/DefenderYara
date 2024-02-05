
rule Trojan_Win64_TempParticle_A_dha{
	meta:
		description = "Trojan:Win64/TempParticle.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,64 00 64 00 01 00 00 64 00 "
		
	strings :
		$a_43_0 = {2b c3 c6 03 e9 41 83 e8 05 ba 0a 00 00 00 44 89 43 01 48 8b cb 44 90 01 04 ff 90 00 00 } //00 5d 
	condition:
		any of ($a_*)
 
}