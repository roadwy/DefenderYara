
rule Trojan_Win64_IcedID_ACS_MTB{
	meta:
		description = "Trojan:Win64/IcedID.ACS!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {8b 7c 24 08 8d 5f 03 85 ff 0f 49 df 83 e3 fc 29 df 83 ff 02 bf 06 45 5b 7a 0f 44 fa eb 91 81 ff 58 4a 05 57 0f 84 a7 00 00 00 81 ff 48 78 eb 66 0f 85 79 ff ff ff 8b 7c 24 04 8d 5f 03 85 ff 0f 49 df 83 e3 fc 29 df 83 ff 01 8b 7c 24 04 89 7c 24 08 } //00 00 
	condition:
		any of ($a_*)
 
}