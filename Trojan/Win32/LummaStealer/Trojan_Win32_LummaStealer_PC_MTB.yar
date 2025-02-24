
rule Trojan_Win32_LummaStealer_PC_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.PC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 bc 1e [0-04] 89 d0 25 [0-04] 89 d9 81 e1 [0-04] 09 c1 81 f1 [0-04] 8d 82 [0-04] 21 c1 09 f9 21 f8 f7 d1 09 c8 04 [0-04] 88 84 1e [0-04] 43 4a 81 fb [0-04] 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}