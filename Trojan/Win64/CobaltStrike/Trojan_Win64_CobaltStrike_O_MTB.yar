
rule Trojan_Win64_CobaltStrike_O_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.O!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {44 8b f8 85 c0 78 ?? 48 83 c6 06 48 ff } //2
		$a_01_1 = {49 8b ce 4c 8b c6 ff 15 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}