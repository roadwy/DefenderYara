
rule Trojan_Win32_ModiLoader_BAA_MTB{
	meta:
		description = "Trojan:Win32/ModiLoader.BAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 06 29 d8 2d ?? ?? ?? ?? 89 02 83 c6 04 41 8b c1 2b 45 18 0f 85 05 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}