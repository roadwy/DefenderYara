
rule Trojan_Win32_Tofsee_MKU_MTB{
	meta:
		description = "Trojan:Win32/Tofsee.MKU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8d 34 29 c1 e9 05 89 44 24 14 8b d9 83 fa 1b 75 ?? ff 15 ?? ?? ?? ?? 8b 44 24 14 03 5c 24 20 c7 05 ?? ?? ?? ?? 00 00 00 00 33 de 33 d8 2b fb 8b d7 c1 e2 04 89 54 24 14 8b 44 24 28 01 44 24 14 81 3d ?? ?? ?? ?? be 01 00 00 8d 1c 2f 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}