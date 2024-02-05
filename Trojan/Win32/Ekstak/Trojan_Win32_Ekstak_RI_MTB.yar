
rule Trojan_Win32_Ekstak_RI_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.RI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {55 8b ec 56 8b 75 14 56 ff 15 90 01 01 e0 46 00 6a 00 e8 90 01 01 3b 04 00 e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Ekstak_RI_MTB_2{
	meta:
		description = "Trojan:Win32/Ekstak.RI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8d 4d f8 51 50 ff 15 90 31 65 00 85 c0 74 0e 8b 45 14 8d 55 fc 52 50 ff 15 c4 30 65 00 e9 } //00 00 
	condition:
		any of ($a_*)
 
}