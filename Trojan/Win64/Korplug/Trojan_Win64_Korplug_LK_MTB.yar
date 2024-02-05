
rule Trojan_Win64_Korplug_LK_MTB{
	meta:
		description = "Trojan:Win64/Korplug.LK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {e9 00 00 00 00 8b 84 24 90 01 01 00 00 00 2d 90 01 08 ff ff e9 00 00 00 00 8b 84 24 90 01 01 00 00 00 2d 90 01 08 ff ff e9 00 00 00 00 8b 84 24 90 01 01 00 00 00 2d 90 01 08 ff ff e9 00 00 00 00 8b 84 24 90 01 01 00 00 00 2d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}