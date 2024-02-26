
rule Trojan_Win32_Ekstak_RH_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.RH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {55 8b ec a1 f0 d4 46 00 ff 75 14 ff d0 e9 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Ekstak_RH_MTB_2{
	meta:
		description = "Trojan:Win32/Ekstak.RH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_01_0 = {55 8b ec 56 e8 b7 6a fb ff e9 } //01 00 
		$a_01_1 = {40 00 00 40 2e 6d 70 67 } //00 00  @䀀洮杰
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Ekstak_RH_MTB_3{
	meta:
		description = "Trojan:Win32/Ekstak.RH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {51 56 57 68 04 01 00 00 6a 00 68 a8 ee 4c 00 e8 fc 01 00 00 83 c4 0c e9 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Ekstak_RH_MTB_4{
	meta:
		description = "Trojan:Win32/Ekstak.RH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {ff 15 6c 32 65 00 8b f0 ff 15 00 33 65 00 85 c0 74 1a 8d 4c 24 04 51 50 ff 15 fc 32 65 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Ekstak_RH_MTB_5{
	meta:
		description = "Trojan:Win32/Ekstak.RH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {55 8b ec 51 56 57 68 88 32 65 00 e8 90 62 fb ff e9 } //01 00 
		$a_01_1 = {55 8b ec 51 56 57 68 88 22 65 00 e8 90 62 fb ff e9 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Ekstak_RH_MTB_6{
	meta:
		description = "Trojan:Win32/Ekstak.RH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {31 65 00 8d 55 f8 c7 45 f8 08 00 00 00 52 c7 45 fc 04 00 00 00 ff 15 90 01 01 30 65 00 c7 45 fc 00 00 00 00 ff 15 90 01 01 31 65 00 ff 15 90 01 02 65 00 e9 90 00 } //01 00 
		$a_01_1 = {44 00 69 00 73 00 6b 00 57 00 72 00 69 00 74 00 65 00 43 00 6f 00 70 00 79 00 5f 00 45 00 78 00 65 00 2e 00 65 00 78 00 65 00 } //00 00  DiskWriteCopy_Exe.exe
	condition:
		any of ($a_*)
 
}