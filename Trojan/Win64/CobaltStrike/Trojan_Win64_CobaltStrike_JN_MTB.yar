
rule Trojan_Win64_CobaltStrike_JN_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.JN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {44 8a 44 0c ?? 41 8d 40 ?? 3c ?? 77 ?? 41 80 e8 ?? 44 88 44 0c ?? 48 ff c1 49 3b ca 7c } //1
		$a_03_1 = {41 8b c1 f7 d8 8d 3c 87 41 69 00 ?? ?? ?? ?? 49 83 c0 ?? 69 f6 ?? ?? ?? ?? 8b c8 c1 e9 ?? 33 c8 69 c9 ?? ?? ?? ?? 33 f1 49 83 e9 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}