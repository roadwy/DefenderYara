
rule Trojan_Win64_CobaltStrike_CCIQ_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.CCIQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {45 8b cd 48 8b cf 80 31 ?? 44 03 ce 48 03 ce 41 81 f9 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}