
rule Trojan_Win64_RandomPhrase_A{
	meta:
		description = "Trojan:Win64/RandomPhrase.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {55 48 89 e5 48 83 ec 40 48 89 75 f8 48 89 f1 48 81 c1 ?? ?? 00 00 e8 ?? ?? ?? ?? 48 89 c6 48 89 05 ?? ?? ?? ?? e8 05 00 00 00 e9 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}