
rule Trojan_Win64_RustyStealer_SMW_MTB{
	meta:
		description = "Trojan:Win64/RustyStealer.SMW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {4c 8b 44 11 08 4c 33 44 08 08 4c 89 84 0d 48 24 00 00 48 83 c1 08 48 83 f9 50 72 e4 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}