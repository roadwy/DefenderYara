
rule Trojan_Win32_LummaStealer_ZZ_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.ZZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_00_0 = {b0 40 c3 b0 3f c3 89 c8 04 d0 3c 09 77 06 80 c1 04 89 c8 c3 } //1
		$a_02_1 = {b0 40 c3 b0 3f c3 80 f9 30 72 ?? 80 f9 39 77 06 80 c1 04 89 c8 c3 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}