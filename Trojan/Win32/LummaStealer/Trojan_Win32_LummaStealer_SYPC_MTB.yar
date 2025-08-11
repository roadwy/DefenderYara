
rule Trojan_Win32_LummaStealer_SYPC_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.SYPC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {20 20 20 20 00 d0 05 00 00 10 00 00 00 d0 05 00 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 e0 2e 72 73 72 63 00 00 00 b0 02 00 00 00 e0 05 00 00 02 00 00 00 e0 05 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0 2e 69 64 61 74 61 20 20 00 10 00 00 00 f0 05 00 00 02 00 00 00 e2 05 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}