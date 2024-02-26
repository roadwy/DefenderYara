
rule Trojan_Win32_Ekstak_RA_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.RA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {e8 d8 67 fb ff eb 0d 8b 75 fc e8 ce 67 fb ff eb 03 8b 75 fc } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Ekstak_RA_MTB_2{
	meta:
		description = "Trojan:Win32/Ekstak.RA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {2b c2 d1 f8 03 c1 8b 4d f0 89 86 c4 00 00 00 8b 45 f8 2b c1 2b 45 dc 99 2b c2 d1 f8 03 c1 89 86 c8 00 cc cc } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Ekstak_RA_MTB_3{
	meta:
		description = "Trojan:Win32/Ekstak.RA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {55 8b ec 51 56 68 90 01 01 30 65 00 6a 01 6a 00 ff 15 90 01 01 f3 64 00 8b f0 85 f6 74 2a ff 15 90 01 01 f3 64 00 3d b7 00 00 00 75 13 56 ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}