
rule Trojan_Win64_Cobaltstrike_EL_MTB{
	meta:
		description = "Trojan:Win64/Cobaltstrike.EL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {2b c1 2b 05 90 01 04 48 63 c8 48 8b 44 24 50 0f b6 0c 08 48 8b 44 24 58 0f b6 2c 10 33 e9 8b 35 90 01 04 0f af 35 90 01 04 8b 3d 90 01 04 0f af 3d 90 01 04 8b 1d 90 01 04 0f af 1d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}