
rule Trojan_Win32_SmokeLoader_GEH_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.GEH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_03_0 = {8d 0c 07 c1 e8 90 01 01 89 45 90 01 01 8b 45 90 01 01 01 45 90 01 01 51 8d 45 90 01 01 50 c7 05 90 01 04 fc 03 cf ff e8 90 01 04 8b 45 90 01 01 33 45 90 00 } //10
		$a_03_1 = {db 66 3b 70 8b 45 90 01 01 8b 4d 90 01 01 31 08 90 00 } //10
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10) >=20
 
}