
rule Trojan_Win32_Ursnif_DEI_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.DEI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b c7 d3 e0 8b cf c1 e9 05 03 8d 90 01 01 fe ff ff 03 85 90 01 01 fe ff ff 33 f6 33 c1 8b 8d 90 01 01 fe ff ff 03 cf 33 c1 29 45 6c 89 35 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}