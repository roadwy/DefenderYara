
rule Trojan_Win32_Tnega_DBV_MTB{
	meta:
		description = "Trojan:Win32/Tnega.DBV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {64 31 00 04 01 0c 00 46 41 4c 44 4c 45 4d 4d 45 4e 45 53 00 04 60 09 08 } //00 00 
	condition:
		any of ($a_*)
 
}