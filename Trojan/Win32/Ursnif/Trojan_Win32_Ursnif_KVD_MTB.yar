
rule Trojan_Win32_Ursnif_KVD_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.KVD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 02 00 "
		
	strings :
		$a_02_0 = {2b d1 0f af c2 33 85 90 01 01 ff ff ff 8b 4d c0 8b 55 90 01 01 03 04 8a 8b 0d 90 01 04 03 8d 90 01 01 fe ff ff 88 01 90 09 06 00 8b 95 90 01 01 ff ff ff 90 00 } //02 00 
		$a_02_1 = {8a 84 3e f5 d0 00 00 8b 0d 90 01 04 88 04 31 8b 4d fc 33 cd 5f e8 90 01 04 c9 c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}