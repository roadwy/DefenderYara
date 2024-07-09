
rule Trojan_Win32_Ursnif_DC_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.DC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 4c 24 10 0f b6 c0 66 2b c3 66 83 c0 09 0f b7 d0 8b 44 24 20 05 9c c1 0d 01 89 54 24 0c 89 01 83 c1 04 a3 ?? ?? ?? ?? a0 ?? ?? ?? ?? 2a c2 89 4c 24 10 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}