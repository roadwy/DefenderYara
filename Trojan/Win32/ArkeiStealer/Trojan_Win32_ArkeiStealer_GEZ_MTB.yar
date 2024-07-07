
rule Trojan_Win32_ArkeiStealer_GEZ_MTB{
	meta:
		description = "Trojan:Win32/ArkeiStealer.GEZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_03_0 = {2b c8 8b 84 24 90 01 04 03 c1 a3 90 01 04 0f be 05 90 01 04 35 c0 b4 00 00 88 44 24 13 39 9c 24 90 00 } //10
		$a_03_1 = {8a 44 24 10 04 90 01 01 02 05 90 01 04 88 44 24 10 0f b7 44 24 24 33 44 24 70 89 44 24 70 eb 90 00 } //10
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10) >=20
 
}