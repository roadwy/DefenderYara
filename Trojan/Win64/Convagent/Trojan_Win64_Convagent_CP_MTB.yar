
rule Trojan_Win64_Convagent_CP_MTB{
	meta:
		description = "Trojan:Win64/Convagent.CP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {49 89 f0 49 29 c0 48 89 c1 ba 90 01 04 e8 90 01 04 48 85 c0 74 90 01 01 8b 08 31 f9 8b 50 90 01 01 44 31 f2 09 ca 74 90 01 01 48 ff c0 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}