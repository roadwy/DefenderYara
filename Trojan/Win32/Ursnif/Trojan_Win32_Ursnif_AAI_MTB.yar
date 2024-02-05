
rule Trojan_Win32_Ursnif_AAI_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.AAI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {81 c1 e0 58 6f 01 89 4c 24 18 89 0b 8b 5c 24 24 89 0d 90 01 04 8d 0c 33 8d 0c 4d 90 01 04 03 cb 81 3d 90 01 04 6e 1e 00 00 89 4c 24 90 01 01 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}