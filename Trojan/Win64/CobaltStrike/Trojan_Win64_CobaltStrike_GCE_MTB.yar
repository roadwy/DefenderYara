
rule Trojan_Win64_CobaltStrike_GCE_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.GCE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {31 04 11 48 83 c2 04 8b 43 3c 35 90 01 04 29 43 38 8b 43 38 2b 43 68 35 90 01 04 01 43 1c 8b 83 90 01 04 01 83 90 01 04 48 81 fa 90 01 04 7c 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}