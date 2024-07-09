
rule Trojan_Win64_Teeplex_A{
	meta:
		description = "Trojan:Win64/Teeplex.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 c0 f0 4d 0f b1 bc f1 ?? ?? ?? ?? 48 8b d8 74 0e 48 3b c7 0f 84 } //1
		$a_03_1 = {41 8b c1 41 ff c1 41 f7 f2 42 0f b6 04 1a 41 2a 40 ff 41 88 40 ff 44 3b ?? 72 df } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}