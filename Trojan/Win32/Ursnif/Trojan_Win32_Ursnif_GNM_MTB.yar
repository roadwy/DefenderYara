
rule Trojan_Win32_Ursnif_GNM_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.GNM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {56 8b 71 04 8b d6 2b d0 2b 54 24 08 8a 12 88 16 8d 50 01 01 51 04 83 ca ff 2b d0 01 54 24 0c } //00 00 
	condition:
		any of ($a_*)
 
}