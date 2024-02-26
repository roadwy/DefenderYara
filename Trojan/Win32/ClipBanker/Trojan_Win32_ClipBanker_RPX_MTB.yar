
rule Trojan_Win32_ClipBanker_RPX_MTB{
	meta:
		description = "Trojan:Win32/ClipBanker.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f b7 c0 b9 82 00 00 00 99 f7 f9 81 c2 c8 00 00 00 52 ff 15 90 01 04 33 c0 66 89 85 e8 bd ff ff 8d 85 e8 bd ff ff 50 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_ClipBanker_RPX_MTB_2{
	meta:
		description = "Trojan:Win32/ClipBanker.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 4c 24 14 56 8b 51 f8 89 54 24 2c ff d3 8b 44 24 28 83 f8 22 8b 44 24 14 0f 85 60 02 00 00 80 38 54 0f 85 52 02 00 00 8b 4c 24 18 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_ClipBanker_RPX_MTB_3{
	meta:
		description = "Trojan:Win32/ClipBanker.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {66 8b 16 3b e3 8d b6 02 00 00 00 81 c9 90 01 04 d3 f0 0f b6 4c 25 00 66 d3 f8 8d ad 01 00 00 00 66 0f b3 e8 32 cb 9f fe c1 0f bd c2 f6 d9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_ClipBanker_RPX_MTB_4{
	meta:
		description = "Trojan:Win32/ClipBanker.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {8a 4d f0 30 4c 05 f1 40 83 f8 0e 72 f3 } //01 00 
		$a_01_1 = {8a 4d bc 30 4c 05 bd 40 83 f8 40 72 f3 } //01 00 
		$a_01_2 = {8a 85 60 ff ff ff 30 84 0d 61 ff ff ff 41 83 f9 10 72 ed } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_ClipBanker_RPX_MTB_5{
	meta:
		description = "Trojan:Win32/ClipBanker.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {0f b6 84 35 08 fe ff ff 88 84 3d 08 fe ff ff 88 8c 35 08 fe ff ff 0f b6 84 3d 08 fe ff ff 8b 8d 9c fc ff ff 03 c2 0f b6 c0 0f b6 84 05 08 fe ff ff 32 44 0d bc 88 84 0d a0 fd ff ff 41 89 8d 9c fc ff ff 83 f9 2a } //00 00 
	condition:
		any of ($a_*)
 
}