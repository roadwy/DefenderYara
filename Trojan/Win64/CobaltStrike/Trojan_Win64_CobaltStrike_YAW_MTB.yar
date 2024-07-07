
rule Trojan_Win64_CobaltStrike_YAW_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.YAW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f 45 c8 b8 90 01 04 44 0f b6 c1 48 8b 4e 10 41 2b e8 41 2b ed 83 c5 90 01 01 f7 ed c1 fa 03 8b c2 c1 e8 1f 03 d0 6b c2 1a 48 8b 56 18 2b e8 41 02 e8 48 3b ca 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}