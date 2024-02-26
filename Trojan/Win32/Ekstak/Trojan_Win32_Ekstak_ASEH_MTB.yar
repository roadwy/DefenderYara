
rule Trojan_Win32_Ekstak_ASEH_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.ASEH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {55 8b ec 51 56 68 90 01 03 00 6a 01 6a 00 ff 15 90 01 03 00 8b f0 85 f6 74 1b ff 15 90 01 03 00 3d b7 00 00 00 75 0e 56 ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}