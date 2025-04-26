
rule Trojan_Win32_Ursnif_GNO_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.GNO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 11 8b de 2b df 03 d3 89 11 83 c1 ?? 48 8b fa } //10
		$a_03_1 = {69 c0 0d 66 19 00 05 5f f3 6e 3c a3 ?? ?? ?? ?? 0f b7 c0 6a 19 99 5b f7 fb 80 c2 61 88 14 31 41 3b cf } //10
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10) >=20
 
}