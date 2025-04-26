
rule Trojan_Win32_Hancitor_GF_MTB{
	meta:
		description = "Trojan:Win32/Hancitor.GF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_02_0 = {83 ea 02 a1 [0-04] 83 d8 00 33 c9 2b 55 ?? 1b c1 89 15 [0-04] 8b 55 ?? 8b 45 ?? 8a 08 88 0a 8b 55 ?? 83 c2 ?? 89 55 ?? 8b 45 ?? 83 c0 ?? 89 45 } //10
		$a_02_1 = {0f b7 55 fc 03 15 [0-04] 03 15 [0-04] 66 89 55 ?? a1 [0-04] 05 [0-04] a3 [0-04] 8b 0d [0-04] 03 4d ?? 8b 15 [0-04] 89 91 [0-04] a1 [0-04] 8b 0d [0-04] 8d 54 01 ?? 66 89 55 ?? e9 } //10
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10) >=20
 
}