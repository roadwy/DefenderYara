
rule Trojan_Win32_Lokibot_SH_MTB{
	meta:
		description = "Trojan:Win32/Lokibot.SH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 03 00 "
		
	strings :
		$a_03_0 = {55 8b ec eb 90 01 01 90 05 10 01 90 8a 45 08 90 05 10 01 90 30 01 90 05 10 01 90 eb 90 01 01 90 05 10 01 90 8b 4d 0c 90 05 10 01 90 eb 90 01 01 90 05 10 01 90 5d c2 90 00 } //01 00 
		$a_03_1 = {8b ca 03 cb c6 01 90 01 01 90 05 10 01 90 43 48 75 90 01 01 33 c0 5b c3 90 00 } //01 00 
		$a_03_2 = {8b da 03 d9 90 05 10 01 90 c6 03 90 01 01 41 48 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Lokibot_SH_MTB_2{
	meta:
		description = "Trojan:Win32/Lokibot.SH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {55 8b ec 83 c4 e4 53 56 57 33 c0 55 68 90 01 04 64 ff 30 64 89 20 e8 90 01 04 89 45 fc 90 02 10 8b 45 fc 89 45 f8 90 02 10 8d 45 e8 50 e8 90 02 10 8b 45 f8 3b 45 fc 0f 90 00 } //01 00 
		$a_03_1 = {8b c8 b2 9c 8b c3 e8 90 01 02 ff ff 90 05 0a 01 90 46 81 fe 90 01 02 00 00 75 90 00 } //01 00 
		$a_03_2 = {8d 55 e8 8d 45 f0 e8 90 01 02 ff ff 8b c8 90 00 } //01 00 
		$a_81_3 = {52 65 73 6f 6c 76 69 6e 67 20 68 6f 73 74 6e 61 6d 65 20 25 73 } //01 00  Resolving hostname %s
		$a_81_4 = {44 69 73 63 6f 6e 6e 65 63 74 69 6e 67 20 66 72 6f 6d 20 25 73 } //00 00  Disconnecting from %s
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Lokibot_SH_MTB_3{
	meta:
		description = "Trojan:Win32/Lokibot.SH!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8a 0c 13 b0 86 02 cb c0 c9 03 f6 d9 c0 c9 03 f6 d1 32 cb f6 d1 80 e9 03 80 f1 8a c0 c1 02 80 f1 33 f6 d1 80 e9 39 d0 c1 2a cb 32 cb 80 c1 59 f6 d1 2a cb 32 cb f6 d9 80 f1 b7 2a c1 f6 d0 2c 55 f6 d0 2c 5e 34 88 2a c3 34 9b 02 c3 c0 c8 03 02 c3 88 04 13 } //00 00 
	condition:
		any of ($a_*)
 
}