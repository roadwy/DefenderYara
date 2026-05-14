
rule Trojan_Win32_Gulpix_ARR_MTB{
	meta:
		description = "Trojan:Win32/Gulpix.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_03_0 = {66 3b d7 74 ?? 0f b7 94 4d ?? ?? ?? ?? 41 66 3b d6 75 } //14
		$a_03_1 = {0f 94 c0 33 f6 8d 7c 00 ?? 33 c0 40 8b c8 66 39 b5 } //6
	condition:
		((#a_03_0  & 1)*14+(#a_03_1  & 1)*6) >=20
 
}