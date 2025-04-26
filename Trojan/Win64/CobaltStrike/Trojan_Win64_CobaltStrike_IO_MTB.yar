
rule Trojan_Win64_CobaltStrike_IO_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.IO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {ff c0 89 85 ?? ?? ?? ?? 8b 45 ?? 39 85 ?? ?? ?? ?? 0f 8d } //1
		$a_03_1 = {48 8b c1 48 8b 8d ?? ?? ?? ?? 48 f7 f1 48 8b c2 48 8b 8d ?? ?? ?? ?? 0f be 04 01 8b 8d ?? ?? ?? ?? 33 c8 8b c1 48 63 8d } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}