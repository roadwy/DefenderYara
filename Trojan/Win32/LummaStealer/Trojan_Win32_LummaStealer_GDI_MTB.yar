
rule Trojan_Win32_LummaStealer_GDI_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.GDI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {03 c2 83 e0 ?? 8a 0c 28 32 cf 32 0e 88 0e } //5
		$a_03_1 = {41 8a 0c 29 43 32 ca 89 5c 24 ?? 32 4c 24 ?? 8b d3 88 0c 30 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}