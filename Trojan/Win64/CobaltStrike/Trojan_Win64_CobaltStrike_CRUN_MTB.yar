
rule Trojan_Win64_CobaltStrike_CRUN_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.CRUN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 83 f1 59 45 88 4c 18 ff 48 ff c0 4c 89 c1 48 3d 9e 03 00 00 7d ?? 4c 8d 41 01 44 0f b6 4c 04 62 66 90 90 4c 39 c2 73 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}