
rule Trojan_Win64_CobaltStrike_J_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.J!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {44 8b c0 48 8d 5b ?? b8 ?? ?? ?? ?? 41 f7 e8 c1 fa ?? 8b ca c1 e9 ?? 03 d1 69 ca ?? ?? ?? ?? 44 2b c1 41 fe c0 44 32 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}