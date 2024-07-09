
rule Trojan_Win32_Polyglot_SIB_MTB{
	meta:
		description = "Trojan:Win32/Polyglot.SIB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {33 c0 89 85 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 8d b5 ?? ?? ?? ?? 8d bd ?? ?? ?? ?? [0-20] 83 c4 18 33 c0 8a 0c 30 c0 f9 ?? 88 0c 47 8a 14 30 80 e2 ?? 88 54 47 ?? 40 3d ?? ?? ?? ?? 7c } //1
		$a_03_1 = {33 c9 8d 49 ?? 33 c0 8b d1 c1 e2 ?? 03 d0 8a 14 3a 88 16 46 83 c0 02 83 f8 ?? 7c ?? 83 c1 02 83 f9 ?? 7c } //1
		$a_03_2 = {f9 ff ff 33 d2 8a 90 90 ?? ?? ?? ?? 90 18 83 f2 33 83 f2 33 8b 45 fc 88 90 90 90 1b 00 8b 4d fc 83 c1 01 89 4d fc 81 7d fc 11 06 00 00 90 18 90 18 8b 45 fc 69 c0 b8 01 00 00 99 b9 dc 00 00 00 f7 f9 90 18 33 d2 8a 90 90 a4 00 41 00 90 18 83 f2 33 83 f2 33 8b 45 fc 88 90 90 a4 00 41 00 8b 4d fc 83 c1 01 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}