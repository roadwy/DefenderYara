
rule Trojan_Win32_Vidar_NDR_MTB{
	meta:
		description = "Trojan:Win32/Vidar.NDR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 05 00 "
		
	strings :
		$a_03_0 = {e8 f5 08 ff ff 0f b6 45 90 01 01 8b 4d f4 8a 55 90 01 01 84 54 01 1d 75 1e 83 7d 10 90 01 01 74 12 8b 4d f0 8b 89 90 01 04 0f b7 04 41 23 45 90 01 01 eb 02 33 c0 85 c0 74 03 33 c0 40 90 00 } //01 00 
		$a_01_1 = {6f 64 79 73 73 65 79 5f 74 67 } //01 00  odyssey_tg
		$a_01_2 = {63 68 69 61 5c 6d 61 69 6e 6e 65 74 5c 77 61 6c 6c 65 74 } //00 00  chia\mainnet\wallet
	condition:
		any of ($a_*)
 
}