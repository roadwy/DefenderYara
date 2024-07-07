
rule Trojan_Win32_Ursnif_DEA_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.DEA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b 4c 24 10 8b 54 24 14 8b c7 d3 e0 8b cf c1 e9 05 03 4c 24 2c 03 44 24 28 03 d7 33 c1 8b 0d 90 01 04 33 c2 2b e8 90 00 } //1
		$a_02_1 = {8b 4c 24 14 8b d7 d3 e2 8b c7 03 54 24 28 c1 e8 05 03 44 24 30 33 d0 c7 05 90 01 04 00 00 00 00 8b 44 24 18 03 c7 33 d0 a1 90 01 04 2b ea 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}