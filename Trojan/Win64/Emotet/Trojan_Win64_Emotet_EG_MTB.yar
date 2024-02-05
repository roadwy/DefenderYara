
rule Trojan_Win64_Emotet_EG_MTB{
	meta:
		description = "Trojan:Win64/Emotet.EG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {41 31 d2 45 88 d3 48 8b 8d 90 01 01 0b 00 00 4c 63 4d 90 01 01 46 88 1c 09 8b 45 90 01 01 83 c0 01 89 45 90 01 01 e9 90 01 01 ff ff ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}