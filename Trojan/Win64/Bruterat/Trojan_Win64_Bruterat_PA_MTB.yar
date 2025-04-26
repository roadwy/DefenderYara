
rule Trojan_Win64_Bruterat_PA_MTB{
	meta:
		description = "Trojan:Win64/Bruterat.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 8b c6 41 ff c1 4d 8d 52 ?? 48 f7 e1 48 8b c1 48 2b c2 48 d1 ?? 48 03 c2 48 c1 e8 ?? 48 6b c0 ?? 48 2b c8 48 2b cb 0f b6 44 0c ?? 43 32 44 13 ?? 41 88 42 ?? 41 81 f9 ?? ?? ?? ?? 72 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}