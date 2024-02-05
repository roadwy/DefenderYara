
rule Trojan_Win32_ICLoader_DSK_MTB{
	meta:
		description = "Trojan:Win32/ICLoader.DSK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_02_0 = {8b 4d 0c 03 4d 08 8b 15 90 01 04 8a 04 11 32 05 90 01 04 8b 4d 0c 03 4d 08 8b 15 90 01 04 88 04 11 8b 45 08 83 c0 01 89 45 08 81 7d 08 44 07 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}