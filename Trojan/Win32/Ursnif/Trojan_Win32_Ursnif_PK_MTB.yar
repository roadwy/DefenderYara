
rule Trojan_Win32_Ursnif_PK_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.PK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {eb 09 8b 45 90 01 01 83 c0 04 89 45 90 01 01 81 7d f0 90 01 02 00 00 73 69 8b 0d 90 01 04 03 4d 90 01 01 8b 91 90 01 02 ff ff 89 15 90 01 04 33 c0 a0 90 01 04 8b 0d 90 01 04 8d 54 01 07 89 15 90 01 04 a1 90 01 04 05 90 01 04 a3 90 01 04 8b 0d 90 01 04 03 4d 90 01 01 8b 15 90 01 04 89 91 90 01 02 ff ff a1 90 01 04 6b c0 29 8b 0d 90 01 04 03 c8 66 89 0d 90 01 04 eb 90 00 } //00 00 
		$a_00_1 = {7e } //15 00 
	condition:
		any of ($a_*)
 
}