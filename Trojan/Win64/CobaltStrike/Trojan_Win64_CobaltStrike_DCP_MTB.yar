
rule Trojan_Win64_CobaltStrike_DCP_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.DCP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 f7 f1 48 8b c2 48 8b d0 48 8b 4c 24 50 e8 ?? ?? ?? ?? 0f be 00 48 8b 4c 24 20 48 8b 54 24 40 48 03 d1 48 8b ca 0f be 09 33 c8 8b c1 48 8b 4c 24 20 48 8b 54 24 40 48 03 d1 48 8b ca 88 01 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}