
rule Trojan_Win32_Ursnif_GBC_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.GBC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_01_0 = {8b 16 85 d2 89 55 ec 74 19 ff 45 08 8a 4d 08 33 d7 8b 7d ec 33 d0 d3 ca 89 16 83 c6 04 ff 4d f4 75 de } //0a 00 
		$a_01_1 = {8a cb d3 c0 33 c6 33 45 0c 8b f0 89 32 83 c2 04 ff 4d 08 75 ce } //00 00 
	condition:
		any of ($a_*)
 
}