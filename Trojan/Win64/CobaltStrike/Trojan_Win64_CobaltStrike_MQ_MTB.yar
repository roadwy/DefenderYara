
rule Trojan_Win64_CobaltStrike_MQ_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.MQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 01 00 00 "
		
	strings :
		$a_03_0 = {b8 ed 73 48 4d 41 f7 e8 c1 fa 04 8b c2 c1 e8 1f 03 d0 0f be c2 6b c8 90 01 01 41 8a c0 41 ff c0 2a c1 04 90 01 01 41 30 01 49 ff c1 41 83 f8 16 7c d2 90 00 } //6
	condition:
		((#a_03_0  & 1)*6) >=6
 
}