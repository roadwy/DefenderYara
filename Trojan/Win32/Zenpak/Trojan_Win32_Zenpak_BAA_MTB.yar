
rule Trojan_Win32_Zenpak_BAA_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.BAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 44 24 28 c1 ef 05 03 c1 03 7c 24 1c 33 f8 8d 04 1a 33 f8 81 fe ?? ?? ?? ?? 75 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}