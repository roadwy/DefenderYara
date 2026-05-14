
rule Trojan_Win64_MaskGramStealer_MK_MTB{
	meta:
		description = "Trojan:Win64/MaskGramStealer.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 01 00 00 "
		
	strings :
		$a_03_0 = {44 89 c8 43 8d 2c 09 41 ff c1 0f af c6 44 8d 65 ?? 48 63 ed 4d 63 e4 8d 50 ?? 89 c8 42 32 14 23 32 14 2b 0f af c7 83 c0 ?? 41 32 04 0b 31 c2 41 88 14 0a 41 83 f9 ?? ?? ?? 45 31 c9 48 ff c1 41 39 c8 } //35
	condition:
		((#a_03_0  & 1)*35) >=35
 
}