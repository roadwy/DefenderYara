
rule Trojan_Win64_CobaltStrike_PAHL_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.PAHL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f b6 c3 42 0f b6 04 00 49 ff c5 43 30 44 35 ff 4d 3b ec 0f } //5
		$a_01_1 = {41 ff c1 49 ff c2 41 f7 e9 c1 fa 04 8b c2 c1 e8 1f 03 d0 6b d2 53 44 2b ca 48 83 eb 01 75 } //1
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}