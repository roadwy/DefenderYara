
rule Trojan_Win64_CobaltStrike_MV_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.MV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {f0 00 22 00 0b 02 0e 24 00 22 24 00 00 7c 09 00 00 00 00 00 86 82 82 02 00 10 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}