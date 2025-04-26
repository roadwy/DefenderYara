
rule Trojan_Win64_CobaltStrike_CCGQ_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.CCGQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 0c 03 02 4c 04 ?? 80 c1 ?? 80 f1 ?? 88 4c ?? 40 48 ff c0 48 83 f8 ?? 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}