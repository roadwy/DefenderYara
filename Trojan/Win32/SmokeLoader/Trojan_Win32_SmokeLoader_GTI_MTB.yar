
rule Trojan_Win32_SmokeLoader_GTI_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.GTI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_03_0 = {8d 0c 03 33 4d 0c 89 35 ?? ?? ?? ?? 33 cf 89 4d f0 8b 45 } //10
		$a_03_1 = {8b c3 c1 e8 ?? 03 45 e0 c7 05 ?? ?? ?? ?? 19 36 6b ff 33 45 0c 33 f8 89 7d } //10
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10) >=20
 
}