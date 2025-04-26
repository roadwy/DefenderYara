
rule Trojan_Win64_CobaltStrike_LKAE_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.LKAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {f3 0f 7f 04 30 41 8d 40 10 41 83 c0 ?? f3 0f 6f 04 30 66 0f fc c8 66 0f ef cb f3 0f 7f 0c 30 3b da 72 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}