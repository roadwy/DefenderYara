
rule Trojan_Win32_Ursnif_GN_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.GN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {81 c3 38 28 00 00 8b c1 99 03 d8 a1 90 01 04 6a 00 13 fa 03 de 8b 15 90 01 04 13 fa 83 c3 bb 89 5d 90 01 01 83 d7 ff 2b d9 8b 0d 90 01 04 83 c0 c4 6a 31 52 89 7d 90 01 01 81 c3 61 01 00 00 56 8d 3c 41 90 00 } //1
		$a_02_1 = {83 c0 07 89 45 90 01 01 0f b7 c6 2b f8 8d 83 90 01 04 52 83 c7 26 66 03 f0 57 66 89 35 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}