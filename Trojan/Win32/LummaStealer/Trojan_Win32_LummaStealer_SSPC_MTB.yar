
rule Trojan_Win32_LummaStealer_SSPC_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.SSPC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {20 20 20 20 00 b0 70 00 00 10 00 00 00 52 2b 00 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 e0 2e 72 73 72 63 00 00 00 bc 0a 01 00 00 c0 70 00 00 0c 01 00 00 62 2b 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0 2e 69 64 61 74 61 20 20 00 10 00 00 00 d0 71 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}