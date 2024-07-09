
rule Trojan_Win32_SmokeLoader_ASL_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.ASL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {89 45 f8 8b 4d fc 33 4d ?? 8b 45 f8 03 45 ?? 33 c1 89 4d fc } //2
		$a_03_1 = {01 45 f8 8b 45 f8 33 45 ?? 31 45 fc 8b 45 fc 29 45 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}