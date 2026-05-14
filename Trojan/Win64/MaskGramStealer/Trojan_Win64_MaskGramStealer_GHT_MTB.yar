
rule Trojan_Win64_MaskGramStealer_GHT_MTB{
	meta:
		description = "Trojan:Win64/MaskGramStealer.GHT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {49 89 c1 41 83 e1 03 46 8a 4c 0c ?? 44 32 0c 01 44 88 0c 02 48 ff c0 41 39 c0 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}