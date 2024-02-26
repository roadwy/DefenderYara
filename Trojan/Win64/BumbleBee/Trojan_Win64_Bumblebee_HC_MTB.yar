
rule Trojan_Win64_Bumblebee_HC_MTB{
	meta:
		description = "Trojan:Win64/Bumblebee.HC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {88 14 01 ff 83 90 01 04 8b 83 90 01 04 8b 4b 90 01 01 83 e9 90 01 01 0f af c1 89 83 90 01 04 48 63 8b 90 01 04 48 8b 83 90 01 04 44 88 04 01 ff 83 90 01 04 8b 43 90 01 01 8b 8b 90 01 04 83 e9 90 01 01 0f af c1 89 43 90 01 01 49 81 f9 90 01 04 0f 8c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}