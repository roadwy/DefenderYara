
rule Trojan_Win32_Ursnif_CCHU_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.CCHU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8d 55 f8 52 8b 45 f8 50 8b 4d 08 51 8b 15 90 01 04 52 ff 55 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}