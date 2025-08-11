
rule Trojan_Win64_LummaStealer_NP_MTB{
	meta:
		description = "Trojan:Win64/LummaStealer.NP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 63 45 18 42 80 34 30 bc 8b 45 18 83 c0 01 89 45 88 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}