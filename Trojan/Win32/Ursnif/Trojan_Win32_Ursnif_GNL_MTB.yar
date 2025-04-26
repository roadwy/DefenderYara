
rule Trojan_Win32_Ursnif_GNL_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.GNL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b c8 8b c6 2b fe 8a 14 07 32 55 0c 88 10 40 49 75 f4 } //10
		$a_01_1 = {33 45 fc 43 33 45 0c 8a cb d3 c8 8b 4d f8 83 c7 04 89 4d fc 89 06 } //10
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10) >=20
 
}