
rule Trojan_Win64_CobaltStrike_CJ_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.CJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {31 c1 48 8b 55 e0 8b 45 d4 48 98 88 0c 02 83 45 d4 01 83 7d d4 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}