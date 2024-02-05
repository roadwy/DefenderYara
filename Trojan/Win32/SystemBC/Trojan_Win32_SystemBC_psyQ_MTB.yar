
rule Trojan_Win32_SystemBC_psyQ_MTB{
	meta:
		description = "Trojan:Win32/SystemBC.psyQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 07 00 "
		
	strings :
		$a_03_0 = {04 1b 83 c0 03 24 fc e8 b4 d5 ff ff 89 65 e8 8b c4 89 45 dc 83 4d fc ff eb 13 6a 01 58 c3 8b 65 e8 33 ff 89 7d dc 83 90 01 03 8b 5d e4 39 7d dc 74 66 53 ff 75 dc ff 75 14 ff 75 10 6a 01 ff 75 20 ff 15 e8 81 41 00 85 c0 74 4d 57 57 53 ff 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}