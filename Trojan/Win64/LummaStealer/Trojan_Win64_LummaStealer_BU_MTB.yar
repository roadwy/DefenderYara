
rule Trojan_Win64_LummaStealer_BU_MTB{
	meta:
		description = "Trojan:Win64/LummaStealer.BU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 31 f5 48 f7 d1 4c 09 c3 48 21 cb 48 09 eb 48 f7 d0 48 31 c3 48 f7 d3 48 21 c3 48 89 5c 24 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}