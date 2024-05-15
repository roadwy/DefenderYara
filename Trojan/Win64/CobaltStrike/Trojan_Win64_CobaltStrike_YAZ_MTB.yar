
rule Trojan_Win64_CobaltStrike_YAZ_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.YAZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {59 49 08 c7 c0 00 00 98 48 83 c1 90 01 01 00 4a 8d 14 01 81 32 dd cc 00 bb aa 44 89 c0 49 83 e8 00 04 48 8d 52 fc 85 c0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}