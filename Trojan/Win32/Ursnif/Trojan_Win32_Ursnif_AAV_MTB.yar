
rule Trojan_Win32_Ursnif_AAV_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.AAV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b7 c1 8b 4c 24 ?? 89 1a 83 c2 ?? 6b f8 ?? ff 4c 24 1c 8b 44 24 0c 89 54 24 ?? 0f 85 90 0a 35 00 81 c3 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}