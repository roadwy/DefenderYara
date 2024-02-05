
rule Trojan_Win32_Shelm_GMH_MTB{
	meta:
		description = "Trojan:Win32/Shelm.GMH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 0a 00 "
		
	strings :
		$a_03_0 = {53 56 57 8b 3d 90 01 04 6a 00 6a 02 c7 85 80 fe ff ff 90 01 04 c7 85 84 fe ff ff 90 01 04 c7 85 88 fe ff ff 90 01 04 c7 85 8c fe ff ff 90 01 04 c7 85 90 01 01 fe ff ff 90 01 04 c7 85 94 fe ff ff 90 01 04 c7 85 98 fe ff ff 90 00 } //01 00 
		$a_03_1 = {4e 56 49 00 c7 85 90 01 04 44 49 41 20 c7 85 90 01 04 43 6f 72 00 90 00 } //01 00 
		$a_01_2 = {51 51 50 43 4c 65 61 6b 53 63 61 6e 2e 65 78 65 } //00 00 
	condition:
		any of ($a_*)
 
}