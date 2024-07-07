
rule Trojan_Win32_LummaStealer_CCCX_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.CCCX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {f6 17 33 d8 8b c3 33 f3 33 c0 8b f0 8b c6 33 c6 8b d8 8b f6 80 07 90 01 01 8b c0 8b f6 8b db 33 d8 8b f0 8b f3 33 de 33 c6 8b f0 80 2f 90 01 01 33 c3 8b f3 33 c6 8b f0 33 c6 33 d8 8b c0 8b f3 33 c6 f6 2f 47 e2 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}