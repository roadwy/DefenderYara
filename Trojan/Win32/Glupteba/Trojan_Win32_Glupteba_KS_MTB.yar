
rule Trojan_Win32_Glupteba_KS_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.KS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_02_0 = {81 ec 1c 04 00 00 a1 ?? ?? ?? ?? 33 c4 89 84 24 18 04 00 00 a1 ?? ?? ?? ?? 53 55 56 57 8b 3d ?? ?? ?? ?? 33 db a3 ?? ?? ?? ?? 33 f6 8d 64 24 00 81 3d ?? ?? ?? ?? c7 01 00 00 75 29 } //10
		$a_00_1 = {3d cb d9 0b 00 75 06 81 c1 00 00 00 00 40 3d 3d a6 15 00 7c eb } //10
	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*10) >=20
 
}