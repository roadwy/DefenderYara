
rule Trojan_Win64_MaskGramStealer_AMK_MTB{
	meta:
		description = "Trojan:Win64/MaskGramStealer.AMK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 89 c1 83 e1 07 8a 4c 0c 08 41 32 0c 01 88 0c 02 48 ff c0 41 39 c0 7f ?? 4d 63 c0 42 c6 04 02 00 48 83 c4 10 5b } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}