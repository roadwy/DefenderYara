
rule Trojan_Win64_CobaltStrike_NQP_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.NQP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {ff c1 4c 63 f1 41 8d 53 ?? 41 0f b6 c8 4d 03 f2 80 e1 f7 83 e2 07 41 32 c8 41 30 0e 41 0f b6 c8 80 e1 fb 41 32 c8 42 30 0c 12 41 8d 4b fd 81 e1 07 00 00 80 7d } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}