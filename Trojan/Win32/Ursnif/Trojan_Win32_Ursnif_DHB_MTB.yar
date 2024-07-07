
rule Trojan_Win32_Ursnif_DHB_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.DHB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f af cf be e0 ff ff ff 69 f9 7d 71 00 00 89 7c 24 90 01 01 8b 4c 24 90 01 01 8b 54 24 90 01 01 81 c2 90 01 04 89 54 24 90 01 01 89 11 8d 0c 75 90 01 04 89 15 90 01 04 0f b7 d9 39 7c 24 90 01 01 72 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}