
rule Trojan_Win64_ShadowPad_ABK_MTB{
	meta:
		description = "Trojan:Win64/ShadowPad.ABK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 8b 54 24 38 48 8d 44 24 60 48 03 54 24 20 48 3b c2 73 1b 48 8b 03 48 3b c7 75 0a 48 8d 05 ?? ?? ?? ?? 48 89 03 48 83 c3 08 48 3b da 72 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}