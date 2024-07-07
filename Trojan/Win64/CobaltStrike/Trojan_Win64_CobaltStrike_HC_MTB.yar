
rule Trojan_Win64_CobaltStrike_HC_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.HC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 8d 0d ab 70 3e 00 48 89 88 90 00 00 00 48 8d 0d 9e 70 3e 00 48 89 88 b0 00 00 00 48 8d 0d 91 70 3e 00 48 89 88 d0 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}