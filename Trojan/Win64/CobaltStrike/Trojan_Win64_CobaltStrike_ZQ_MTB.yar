
rule Trojan_Win64_CobaltStrike_ZQ_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.ZQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {f7 eb 03 d3 c1 fa 05 8b c2 c1 e8 1f 03 d0 0f be c2 6b d0 ?? 0f b6 c3 2a c2 04 ?? 41 30 00 ff c3 4d 8d 40 01 83 fb 12 7c } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}