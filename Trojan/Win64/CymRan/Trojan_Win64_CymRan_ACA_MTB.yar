
rule Trojan_Win64_CymRan_ACA_MTB{
	meta:
		description = "Trojan:Win64/CymRan.ACA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {48 8b 44 24 40 48 83 b8 b8 00 00 00 ff 74 1f ff 15 84 89 03 00 83 f8 06 75 12 48 8b 44 24 40 48 c7 } //00 00 
	condition:
		any of ($a_*)
 
}