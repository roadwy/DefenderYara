
rule Trojan_Win32_Ursnif_DD_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.DD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a 44 24 20 8b df 2a c1 89 1d 90 01 04 8b 4c 24 0c 04 53 02 c6 8b 09 81 c1 3c 36 0e 01 89 0d 90 01 04 8b 0d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}