
rule Trojan_Win32_Glupteba_KA_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.KA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_02_0 = {81 ec 1c 04 00 00 a1 ?? ?? ?? ?? 33 c4 89 84 24 18 04 00 00 a1 ?? ?? ?? ?? 53 55 56 57 8b 3d ?? ?? ?? ?? 33 db a3 ?? ?? ?? ?? 33 f6 8d 64 24 00 81 3d ?? ?? ?? ?? c7 01 00 00 75 29 } //10
		$a_02_1 = {81 fe cc 6b 84 00 75 0b b8 15 00 00 00 01 05 ?? ?? ?? ?? 46 81 fe c5 0a 26 01 7c af } //10
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10) >=20
 
}