
rule Trojan_Win32_Gracewire_MB_MTB{
	meta:
		description = "Trojan:Win32/Gracewire.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 45 bc 83 c0 90 01 01 89 45 bc 83 7d bc 90 01 01 7d 23 c7 45 b8 90 01 04 c7 45 f8 90 01 04 8b 4d b8 81 e1 90 01 02 00 00 03 4d f8 0f af 4d f8 89 4d f8 eb ce 90 00 } //01 00 
		$a_03_1 = {8b 55 e4 83 c2 90 01 01 89 55 e4 81 7d e4 90 01 02 00 00 73 16 8b 85 90 01 04 03 45 e4 8b 4d e4 8a 91 90 01 04 88 10 eb d8 90 00 } //00 00 
		$a_00_2 = {5d } //04 00 
	condition:
		any of ($a_*)
 
}