
rule Trojan_Win64_CobaltStrike_MKVG_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.MKVG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 c8 99 f7 fb 0f b6 04 17 30 04 0e 8d 41 ?? 99 f7 fb 0f b6 04 17 30 44 0e ?? 48 83 c1 ?? 48 39 cd 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}