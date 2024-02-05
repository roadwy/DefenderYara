
rule Trojan_Win32_Azorult_DX_MTB{
	meta:
		description = "Trojan:Win32/Azorult.DX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 03 8a 0c 10 8a 5c 10 01 8a 6c 10 02 8a 54 10 03 88 55 0b c0 65 0b 02 8a 45 0b 24 c0 0a c8 8a c2 c0 e0 06 80 e2 fc 88 45 0b 0a e8 8b 45 f0 c0 e2 04 0a d3 88 0c 06 88 54 06 01 83 c6 02 89 75 f8 88 2c 06 8d 4d f8 e8 90 02 08 8b 55 f4 03 55 fc 8b 75 f8 8b 5d ec 89 55 f4 3b 17 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}