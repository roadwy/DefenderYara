
rule Trojan_Win64_CobaltStrike_ALAB_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.ALAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {3b cf 73 09 80 34 0b ?? 41 3b cf 72 f7 ff d3 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}