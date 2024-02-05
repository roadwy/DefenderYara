
rule Trojan_Win32_Ursnif_BF_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.BF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {83 e9 4e 0f b6 15 90 01 04 2b ca 89 0d 90 01 04 a1 90 01 04 03 45 90 01 01 8b 88 90 01 04 89 0d 90 01 04 8b 55 90 01 01 0f af 15 90 01 04 03 15 90 01 04 89 15 90 01 04 6b 05 90 00 } //01 00 
		$a_02_1 = {33 c9 8b 55 90 01 01 2b d0 8b 45 90 01 01 1b c1 8b 4d 90 01 01 33 f6 2b ca 1b f0 89 4d 90 01 01 8b 15 90 01 04 81 c2 90 01 04 89 15 90 01 04 a1 90 01 04 03 45 90 01 01 8b 0d 90 01 04 89 88 90 01 04 8b 55 90 01 01 81 ea 90 01 04 2b 15 90 01 04 03 55 fc 03 55 fc 89 55 fc 6b 45 fc 90 01 01 0f b6 0d 90 01 04 03 c1 90 00 } //00 00 
		$a_00_2 = {5d } //04 00 
	condition:
		any of ($a_*)
 
}