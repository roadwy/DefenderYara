
rule Trojan_Win32_RedLineStealer_FX_MTB{
	meta:
		description = "Trojan:Win32/RedLineStealer.FX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_02_0 = {89 45 fc 8b 45 8c 01 45 fc c1 e6 04 03 75 88 33 f2 81 3d ?? ?? ?? ?? 21 01 00 00 } //10
		$a_02_1 = {c7 85 50 fe ff ff bb e5 ad 07 c7 85 ?? ?? ?? ?? c5 b1 6b 00 c7 85 ?? ?? ?? ?? 66 dd 60 43 c7 85 ?? ?? ?? ?? 4a d0 8a 2c c7 85 ?? ?? ?? ?? 15 6e 75 0e c7 85 ?? ?? ?? ?? 8e 52 57 39 c7 85 ?? ?? ?? ?? 5b 4a 15 44 c7 85 } //10
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10) >=20
 
}