
rule Trojan_Win32_Ekstak_ASGD_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.ASGD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {4b 00 85 c0 74 0c 8d 4c 24 00 51 50 ff 15 90 01 02 4b 00 8b 44 24 00 59 c3 90 00 } //02 00 
		$a_03_1 = {55 8b ec 83 ec 0c 53 56 57 e8 90 01 02 f5 ff 89 45 fc e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}