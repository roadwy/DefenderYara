
rule Trojan_Win32_Ekstak_ASFE_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.ASFE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {56 8b 74 24 08 57 8b 3d a8 15 4b 00 6a 10 c7 06 00 00 00 00 ff d7 66 85 c0 } //01 00 
		$a_03_1 = {55 8b ec 83 ec 0c 53 56 57 68 90 01 02 4b 00 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}