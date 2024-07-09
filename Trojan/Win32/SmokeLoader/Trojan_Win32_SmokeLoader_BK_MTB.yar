
rule Trojan_Win32_SmokeLoader_BK_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.BK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {c1 e8 05 03 45 ec 03 f2 33 c6 33 45 fc c7 05 [0-04] 19 36 6b ff 89 45 f4 8b 45 f4 29 45 08 83 65 0c 00 8b 45 dc 01 45 0c 2b 7d 0c ff 4d f0 8b 45 08 89 7d f4 0f } //2
		$a_01_1 = {8d 0c 07 8b d0 c1 ea 05 03 55 e8 c1 e0 04 03 45 e0 89 4d fc 33 d0 33 d1 52 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}