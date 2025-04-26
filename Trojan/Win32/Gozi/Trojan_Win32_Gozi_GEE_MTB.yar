
rule Trojan_Win32_Gozi_GEE_MTB{
	meta:
		description = "Trojan:Win32/Gozi.GEE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b 45 e8 be ?? ?? ?? ?? 8d 7d ?? a5 a5 a5 8b 55 ?? 33 55 ?? 8d 71 ?? 03 55 ?? 8b ce 03 55 [0-06] d3 ea 52 8b 55 ?? 8d 0c 02 e8 ?? ?? ?? ?? 8b 4d ?? 8b 41 ?? 2b 41 ?? 81 45 ?? 00 10 00 00 03 41 ?? 8b ce 3b cb a3 ?? ?? ?? ?? 72 } //10
		$a_02_1 = {03 c6 89 01 8b f7 83 c1 04 [0-04] 75 } //10
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10) >=20
 
}