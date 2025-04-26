
rule Trojan_Win64_CobaltStrike_MS_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.MS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {f0 00 23 00 0b 02 0e 1d 00 ba 08 00 00 14 7f 00 00 00 00 00 33 2f 56 02 00 10 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}