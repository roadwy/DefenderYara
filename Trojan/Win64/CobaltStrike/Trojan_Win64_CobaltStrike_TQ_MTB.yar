
rule Trojan_Win64_CobaltStrike_TQ_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.TQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b6 44 14 ?? 8d 48 ?? 80 f9 ?? 77 ?? 2c ?? 88 44 14 ?? 48 ff c2 48 3b d6 } //1
		$a_03_1 = {8b c8 c1 e9 ?? 33 c8 69 c9 ?? ?? ?? ?? 33 e9 49 83 e8 ?? 75 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}