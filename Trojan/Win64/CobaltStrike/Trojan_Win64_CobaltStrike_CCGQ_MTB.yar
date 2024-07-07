
rule Trojan_Win64_CobaltStrike_CCGQ_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.CCGQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 0c 03 02 4c 04 90 01 01 80 c1 90 01 01 80 f1 90 01 01 88 4c 90 01 01 40 48 ff c0 48 83 f8 90 01 01 75 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}