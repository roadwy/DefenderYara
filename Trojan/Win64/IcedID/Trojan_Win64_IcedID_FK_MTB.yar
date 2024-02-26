
rule Trojan_Win64_IcedID_FK_MTB{
	meta:
		description = "Trojan:Win64/IcedID.FK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_02_0 = {8a 44 94 40 42 02 44 84 90 01 01 43 32 04 33 42 8b 4c 84 90 01 01 41 88 04 1b 83 e1 07 8b 44 94 90 01 01 49 ff c3 d3 c8 ff c0 89 44 94 40 8b c8 42 8b 44 84 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}