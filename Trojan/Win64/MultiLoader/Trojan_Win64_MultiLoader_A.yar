
rule Trojan_Win64_MultiLoader_A{
	meta:
		description = "Trojan:Win64/MultiLoader.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 8b c8 48 8b d8 48 63 78 ?? 48 03 f8 48 8b d7 e8 ?? ?? ?? ?? 8b 57 28 48 03 d3 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}