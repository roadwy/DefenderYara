
rule Trojan_Win64_CobaltStrike_AC_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 10 0f b6 ca 80 f1 03 88 08 41 f6 c0 01 75 90 01 01 80 f2 01 88 10 41 ff c0 48 ff c0 45 3b c1 72 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}