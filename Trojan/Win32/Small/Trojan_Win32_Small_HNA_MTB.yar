
rule Trojan_Win32_Small_HNA_MTB{
	meta:
		description = "Trojan:Win32/Small.HNA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {b9 22 00 00 00 8b d9 51 83 eb 01 6b db 04 81 c3 ?? ?? ?? ?? 68 ?? ?? ?? ?? ff 33 e8 ?? ?? ?? 00 6a 04 } //1
		$a_03_1 = {51 6a 64 e8 ?? ?? ?? ?? 59 e2 f5 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}