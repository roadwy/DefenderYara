
rule Trojan_Win32_Ekstak_BP_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.BP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {55 8b ec 56 6a 19 6a 14 6a 0b 6a 0a 68 90 02 03 00 ff 15 90 02 04 8b 75 14 56 ff 15 90 02 04 e9 90 00 } //05 00 
		$a_03_1 = {55 8b ec 56 68 28 90 01 01 46 00 ff 15 90 02 04 e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}