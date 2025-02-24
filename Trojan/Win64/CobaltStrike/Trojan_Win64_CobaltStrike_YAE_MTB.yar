
rule Trojan_Win64_CobaltStrike_YAE_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.YAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {49 8b c4 48 f7 e6 48 d1 ea 48 6b c2 0b 48 2b f0 32 5c 34 ?? 88 19 41 ff c6 49 63 f6 } //10
		$a_03_1 = {4b 7a 55 59 c7 ?? ?? ?? 56 55 35 44 66 ?? ?? ?? ?? 59 32 c6 44 } //1
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*1) >=11
 
}