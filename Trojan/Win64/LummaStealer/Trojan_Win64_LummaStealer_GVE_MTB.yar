
rule Trojan_Win64_LummaStealer_GVE_MTB{
	meta:
		description = "Trojan:Win64/LummaStealer.GVE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {69 08 95 e9 d1 5b 89 cb c1 eb 18 31 cb 69 cb 95 e9 d1 5b 69 ff 95 e9 d1 5b 31 cf 48 83 c0 04 83 c2 fc 83 fa 07 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}