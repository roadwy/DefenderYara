
rule Trojan_Win32_Redline_UY_MTB{
	meta:
		description = "Trojan:Win32/Redline.UY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 0a 00 "
		
	strings :
		$a_03_0 = {89 d0 c1 e8 02 89 c2 8b 45 08 01 d0 0f b6 00 0f be d0 89 d0 c1 e0 06 8d 0c 10 ba 90 01 04 89 c8 f7 ea c1 fa 03 89 c8 c1 f8 1f 29 c2 89 d0 c1 e0 05 89 c1 8b 55 f0 8b 45 0c 01 d0 31 cb 89 da 88 10 83 45 f0 01 90 00 } //01 00 
		$a_01_1 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //00 00  VirtualProtect
	condition:
		any of ($a_*)
 
}