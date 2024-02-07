
rule Trojan_Win32_SpyStealer_XV_MTB{
	meta:
		description = "Trojan:Win32/SpyStealer.XV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 0a 00 "
		
	strings :
		$a_03_0 = {0f be da 89 9d 4c ff ff ff 90 01 02 83 ca 90 01 01 0f be da 89 9d 90 01 04 8b 9d 90 01 04 33 9d 90 01 04 69 db 90 01 04 89 9d 90 01 04 eb 90 00 } //01 00 
		$a_01_1 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //00 00  VirtualProtect
	condition:
		any of ($a_*)
 
}