
rule Trojan_Win64_Pmax_AP_MTB{
	meta:
		description = "Trojan:Win64/Pmax.AP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 8d 05 68 53 01 00 48 89 15 79 53 01 00 48 8d 15 71 cb 00 00 48 89 0d 53 55 01 00 48 83 c1 30 48 89 15 90 53 01 00 48 8d 15 61 cb 00 00 48 89 0d 42 55 01 00 48 83 c1 30 48 89 05 1f 55 01 00 48 8b 05 08 eb 00 00 48 89 15 99 53 01 00 48 8d 15 43 cb 00 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}