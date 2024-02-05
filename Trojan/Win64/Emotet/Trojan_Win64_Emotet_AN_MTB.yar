
rule Trojan_Win64_Emotet_AN_MTB{
	meta:
		description = "Trojan:Win64/Emotet.AN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 01 00 00 06 00 "
		
	strings :
		$a_01_0 = {0f b6 5c 1c 20 32 5c 17 ff 88 5c 38 ff 48 81 ff 35 0b 00 00 74 16 89 f9 83 e1 0f 0f b6 4c 0c 20 32 0c 17 88 0c 38 } //00 00 
	condition:
		any of ($a_*)
 
}