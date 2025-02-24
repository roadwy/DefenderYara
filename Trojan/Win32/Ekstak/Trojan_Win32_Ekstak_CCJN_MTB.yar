
rule Trojan_Win32_Ekstak_CCJN_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.CCJN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 c8 8b c1 33 cf 5f 81 f9 ?? ?? ?? ?? 5e } //3
		$a_03_1 = {32 c8 8b 44 24 58 88 0d ?? ?? ?? ?? 8a 0d ?? ?? ?? ?? 80 c9 08 c0 e9 03 81 e1 ?? ?? ?? ?? 89 4c 24 } //2
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}