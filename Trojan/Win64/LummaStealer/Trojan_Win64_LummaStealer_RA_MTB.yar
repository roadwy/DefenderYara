
rule Trojan_Win64_LummaStealer_RA_MTB{
	meta:
		description = "Trojan:Win64/LummaStealer.RA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 b8 55 e4 28 b2 b8 67 2a af 5f 44 0f 44 c0 bb eb a2 46 1d } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}