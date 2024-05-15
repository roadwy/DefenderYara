
rule Trojan_Win64_IcedID_LD_MTB{
	meta:
		description = "Trojan:Win64/IcedID.LD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {48 29 c2 8b 85 90 01 04 0f af 85 90 01 04 0f af 85 90 01 04 48 98 48 29 c2 48 89 d0 0f b6 84 05 90 01 04 44 31 c8 41 88 00 48 83 85 90 01 05 48 8b 85 90 01 04 48 39 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}