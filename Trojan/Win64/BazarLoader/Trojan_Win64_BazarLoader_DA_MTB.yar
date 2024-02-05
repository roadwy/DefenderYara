
rule Trojan_Win64_BazarLoader_DA_MTB{
	meta:
		description = "Trojan:Win64/BazarLoader.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {0f b6 1f 41 88 1f 0f b6 5c 4a 01 88 1f 80 07 97 0f b6 1f 41 08 1f 41 0f b6 1c 24 41 30 1f 41 80 04 24 01 41 0f b6 1f 88 1c 08 } //00 00 
	condition:
		any of ($a_*)
 
}