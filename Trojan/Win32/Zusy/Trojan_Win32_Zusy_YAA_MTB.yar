
rule Trojan_Win32_Zusy_YAA_MTB{
	meta:
		description = "Trojan:Win32/Zusy.YAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 02 3b 42 cc 75 ?? 8b 84 24 ?? ?? ?? ?? 0f af 84 24 ?? ?? ?? ?? 8b 94 24 ?? ?? ?? ?? 2b d0 33 da } //4
		$a_01_1 = {8a 00 8b 8c 24 54 03 00 00 34 9a 89 8c 24 08 03 00 00 04 69 88 02 } //1
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}