
rule Trojan_Win64_CobaltStrike_GV_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.GV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {b8 07 18 60 80 4d 8d 40 01 f7 e7 8b c7 8b cf 2b c2 ff c7 d1 e8 03 c2 c1 e8 0d 69 c0 a0 2a 00 00 2b c8 48 63 c1 0f b6 0c 18 41 30 48 ff 41 3b f9 7c } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}