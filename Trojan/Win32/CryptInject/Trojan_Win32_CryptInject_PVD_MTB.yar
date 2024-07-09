
rule Trojan_Win32_CryptInject_PVD_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.PVD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8a 14 19 88 14 38 8a 83 ?? ?? ?? ?? 84 c0 75 ?? a1 ?? ?? ?? ?? 8a 0d ?? ?? ?? ?? 03 c3 03 c7 30 08 83 3d ?? ?? ?? ?? 03 76 } //2
		$a_00_1 = {8b 44 24 10 6a 24 33 d2 5f 8d 0c 06 8b c6 f7 f7 8b 44 24 0c 8a 04 02 30 01 46 3b 74 24 14 75 } //2
	condition:
		((#a_02_0  & 1)*2+(#a_00_1  & 1)*2) >=2
 
}