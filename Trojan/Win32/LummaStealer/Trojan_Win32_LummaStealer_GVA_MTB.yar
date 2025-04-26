
rule Trojan_Win32_LummaStealer_GVA_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.GVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {02 ca 8a 8c 0d ?? ?? ?? ?? 90 13 30 0e ff c6 90 13 ff cf 90 13 fe c3 90 13 8a 94 1d ?? ?? ?? ?? 02 c2 8a 8c 05 ?? ?? ?? ?? 90 13 88 8c 1d ?? ?? ?? ?? 88 94 05 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}