
rule Trojan_Win32_SmokeLoader_BL_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.BL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 45 f8 03 c1 89 45 0c 8b c1 c1 e8 05 89 45 08 8b 45 e8 01 45 08 c1 e1 04 03 4d ec 8d 45 fc 33 4d 08 33 d2 33 4d 0c 89 15 [0-04] 51 50 89 4d 08 } //2
		$a_03_1 = {c1 e8 05 c7 05 [0-04] 19 36 6b ff 89 45 08 8b 45 e4 01 45 08 03 f3 33 75 08 8d 45 f4 33 75 0c } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}