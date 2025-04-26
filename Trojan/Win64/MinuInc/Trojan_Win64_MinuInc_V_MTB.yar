
rule Trojan_Win64_MinuInc_V_MTB{
	meta:
		description = "Trojan:Win64/MinuInc.V!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {4d 00 69 00 6e 00 75 00 65 00 74 00 73 00 4f 00 73 00 20 00 49 00 6e 00 63 00 } //2 MinuetsOs Inc
	condition:
		((#a_01_0  & 1)*2) >=2
 
}