
rule Trojan_Win64_CobaltStrike_JKT_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.JKT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 d2 48 8d 0c 2f 48 8b c7 48 ff c7 49 f7 f1 0f b6 44 14 20 32 04 0b 88 01 48 3b fe 72 e2 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}