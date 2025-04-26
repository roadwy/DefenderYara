
rule Trojan_Win64_CobaltStrike_OFF_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.OFF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 d2 4d 8d 49 01 41 8b c0 41 ff c0 41 f7 f2 0f b6 54 14 48 41 30 51 ff 44 3b c6 72 e3 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}