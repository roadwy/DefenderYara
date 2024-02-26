
rule Trojan_Win64_IcedID_HAT_MTB{
	meta:
		description = "Trojan:Win64/IcedID.HAT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {41 8b c3 41 ff c3 83 e0 0f 8a 44 84 20 30 02 48 ff c2 45 3b d8 72 } //01 00 
		$a_01_1 = {41 8b c2 41 ff c2 83 e0 0f 8a 44 84 60 30 02 48 ff c2 45 3b d0 72 } //00 00 
	condition:
		any of ($a_*)
 
}