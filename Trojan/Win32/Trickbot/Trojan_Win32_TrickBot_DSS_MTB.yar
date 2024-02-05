
rule Trojan_Win32_TrickBot_DSS_MTB{
	meta:
		description = "Trojan:Win32/TrickBot.DSS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 02 00 "
		
	strings :
		$a_02_0 = {55 8b ec 51 53 56 6a 04 33 c0 ba 05 2e 00 00 5b 0f b6 88 90 01 04 81 f9 ff 00 00 00 0f 87 90 01 04 ff 24 8d 90 01 04 c6 80 90 01 04 00 e9 90 01 04 c6 80 90 01 04 01 e9 90 01 04 c6 80 90 01 04 02 e9 90 00 } //01 00 
		$a_02_1 = {55 8b ec 83 ec 24 a1 90 01 04 33 c5 89 45 fc c7 45 e0 90 01 04 c7 45 f0 00 00 00 00 c7 45 dc 00 00 00 00 c7 45 f0 00 00 00 00 eb 90 00 } //01 00 
		$a_02_2 = {8b 45 f0 83 c0 01 89 45 f0 81 7d f0 05 2e 00 00 0f 83 90 01 04 8b 4d f0 0f b6 91 90 01 04 89 55 e8 81 7d e8 ff 00 00 00 0f 87 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}