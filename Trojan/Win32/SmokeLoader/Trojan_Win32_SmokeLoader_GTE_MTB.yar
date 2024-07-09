
rule Trojan_Win32_SmokeLoader_GTE_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.GTE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b c2 c1 e8 ?? 03 45 ec 68 ?? ?? ?? ?? 33 45 0c c7 05 ?? ?? ?? ?? 19 36 6b ff 33 c7 2b d8 } //10
		$a_01_1 = {01 45 fc 8b 45 fc 33 45 0c 8b 4d 08 89 01 c9 c2 0c 00 c2 08 00 55 8b ec 8b 4d 08 } //10
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*10) >=20
 
}