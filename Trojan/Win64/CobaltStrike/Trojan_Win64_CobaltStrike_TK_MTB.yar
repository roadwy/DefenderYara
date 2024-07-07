
rule Trojan_Win64_CobaltStrike_TK_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.TK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 0f b6 0a 88 08 48 ff c0 b9 90 01 04 66 d1 eb 4c 03 d1 66 85 dd 0f 85 90 01 04 4c 3b d7 0f 82 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}