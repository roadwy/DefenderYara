
rule Trojan_Win64_IcedID_SP_MTB{
	meta:
		description = "Trojan:Win64/IcedID.SP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f b6 00 44 90 01 02 41 90 01 02 83 45 90 01 02 8b 45 90 01 01 8b 0d 90 01 04 8b 15 90 01 04 0f af d1 8b 4d 90 01 01 29 d1 8b 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}