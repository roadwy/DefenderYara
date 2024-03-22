
rule Trojan_Win32_Ekstak_ASFC_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.ASFC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {8b ec 83 ec 08 56 68 90 01 02 65 00 e8 5f 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Ekstak_ASFC_MTB_2{
	meta:
		description = "Trojan:Win32/Ekstak.ASFC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {6a 4a 56 ff d7 5f eb 90 01 01 68 90 01 02 65 00 6a 01 6a 00 ff 15 90 01 02 65 00 85 c0 90 00 } //05 00 
		$a_03_1 = {55 8b ec 81 ec ac 01 00 00 53 56 57 8d 85 90 01 02 ff ff 50 68 02 02 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}