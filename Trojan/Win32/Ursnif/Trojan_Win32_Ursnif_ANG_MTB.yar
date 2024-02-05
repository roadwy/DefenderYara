
rule Trojan_Win32_Ursnif_ANG_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.ANG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {03 4d fc 8b 15 90 01 04 89 91 90 01 02 ff ff a1 90 0a 30 00 a1 90 01 04 05 90 01 04 a3 90 01 04 8b 0d 90 00 } //01 00 
		$a_02_1 = {03 4d f4 8b 15 90 01 04 89 91 90 01 02 ff ff 90 0a 30 00 a1 90 01 04 05 90 01 04 a3 90 01 04 8b 0d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}