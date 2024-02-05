
rule Trojan_Win32_ZWrap_AB_MTB{
	meta:
		description = "Trojan:Win32/ZWrap.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {00 8a 0c 02 8b 44 90 01 02 8b 7c 90 01 02 30 0c 38 40 3b 44 90 01 02 89 44 90 01 02 0f 90 02 06 8b 44 90 01 02 8a 54 90 01 02 8a 4c 90 01 02 5f 5e 5d 90 02 10 c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}