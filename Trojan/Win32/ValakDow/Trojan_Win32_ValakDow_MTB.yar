
rule Trojan_Win32_ValakDow_MTB{
	meta:
		description = "Trojan:Win32/ValakDow!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {0f b6 c1 66 2b d0 8b 44 24 10 66 83 c2 03 04 19 02 c0 66 89 15 90 01 04 89 44 24 10 8b d3 83 44 24 20 04 8a c1 02 c0 8a e9 02 e8 8a 44 24 0f 02 c5 28 44 24 10 83 6c 24 38 01 0f 85 90 01 02 ff ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}