
rule Trojan_Win64_CobaltStrike_SPRY_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.SPRY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_01_0 = {42 0f b6 54 37 10 49 8d 47 01 42 32 94 3b e8 03 00 00 42 88 14 36 83 e0 0f 49 83 c6 01 49 89 c7 4d 39 f5 7f 12 49 39 ee 0f 8c 80 fd ff ff e9 2b ff ff ff 0f 1f 40 00 48 85 c0 75 c4 } //3
	condition:
		((#a_01_0  & 1)*3) >=3
 
}