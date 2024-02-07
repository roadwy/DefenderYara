
rule Trojan_Win32_PSWStealer_GNT_MTB{
	meta:
		description = "Trojan:Win32/PSWStealer.GNT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 0a 00 "
		
	strings :
		$a_01_0 = {89 45 e8 8b 45 e8 0f b6 84 05 e8 fe ff ff 8b 4d 08 03 4d ec 0f b6 09 33 c8 8b 45 08 03 45 ec 88 08 e9 3f ff ff ff } //01 00 
		$a_01_1 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //01 00  VirtualProtect
		$a_01_2 = {53 79 73 74 65 6d 46 75 6e 63 74 69 6f 6e 30 33 36 } //00 00  SystemFunction036
	condition:
		any of ($a_*)
 
}