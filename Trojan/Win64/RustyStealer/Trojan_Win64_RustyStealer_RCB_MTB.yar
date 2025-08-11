
rule Trojan_Win64_RustyStealer_RCB_MTB{
	meta:
		description = "Trojan:Win64/RustyStealer.RCB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {49 39 d5 0f 83 fe 00 00 00 49 83 fd 40 0f 83 e8 00 00 00 42 32 34 28 42 88 b4 2c c0 01 00 00 eb ac } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}