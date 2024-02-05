
rule Trojan_Win32_Ursnif_MS_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.MS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b c3 29 05 90 02 04 8b 90 02 03 8a 90 02 03 8b 90 02 03 2a d1 83 90 02 04 05 90 02 04 80 90 02 02 89 07 83 90 02 04 8b 90 02 03 88 90 02 03 a3 90 02 04 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}