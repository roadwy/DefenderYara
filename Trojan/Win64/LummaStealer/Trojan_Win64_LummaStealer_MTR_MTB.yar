
rule Trojan_Win64_LummaStealer_MTR_MTB{
	meta:
		description = "Trojan:Win64/LummaStealer.MTR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {65 48 8b 04 25 60 00 00 00 48 89 84 24 80 01 00 00 48 8b 84 24 80 01 00 00 48 8b 40 18 48 89 84 24 78 01 00 00 48 8b 84 24 78 01 00 00 48 8b 40 20 48 89 84 24 68 01 00 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}