
rule Trojan_Win32_Ursnif_RAA_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.RAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_02_0 = {8b 55 f8 81 c1 04 c7 80 01 89 0a 66 89 3d 90 01 04 8b 15 90 01 04 2b d0 0f b7 c2 90 00 } //1
		$a_02_1 = {81 c5 10 8e 07 01 2b d0 8b 44 24 90 01 01 66 03 f2 66 89 35 90 01 04 89 28 83 c0 90 01 01 ff 4c 24 90 01 01 89 44 24 90 01 01 0f 85 90 00 } //1
		$a_02_2 = {81 c1 6c 86 34 01 0f b7 c0 89 0e 8b 74 24 90 01 01 89 44 24 90 01 01 89 4c 24 90 01 01 89 0d 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1) >=1
 
}