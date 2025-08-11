
rule Trojan_Win32_LummaStealer_GVA_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.GVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f 9c c0 0f 9c 44 24 ?? 30 c3 89 da f6 d2 20 c2 89 d0 30 d8 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_LummaStealer_GVA_MTB_2{
	meta:
		description = "Trojan:Win32/LummaStealer.GVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {02 ca 8a 8c 0d ?? ?? ?? ?? 90 13 30 0e ff c6 90 13 ff cf 90 13 fe c3 90 13 8a 94 1d ?? ?? ?? ?? 02 c2 8a 8c 05 ?? ?? ?? ?? 90 13 88 8c 1d ?? ?? ?? ?? 88 94 05 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}