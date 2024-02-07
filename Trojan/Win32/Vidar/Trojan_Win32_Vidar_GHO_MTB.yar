
rule Trojan_Win32_Vidar_GHO_MTB{
	meta:
		description = "Trojan:Win32/Vidar.GHO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 0a 00 "
		
	strings :
		$a_01_0 = {0f b7 1b 89 e8 05 04 00 00 00 33 18 81 c3 a6 88 2d 68 89 e8 05 04 00 00 00 31 18 81 e3 ff ff 00 00 c1 e3 02 01 d9 8b 31 89 ef 81 c7 dc 00 00 00 8b 3f 81 c7 09 00 00 00 8b 0f 89 ef 81 c7 dc 00 00 00 01 0f ff e6 } //01 00 
		$a_01_1 = {2e 77 69 6e 6c 69 63 65 } //00 00  .winlice
	condition:
		any of ($a_*)
 
}