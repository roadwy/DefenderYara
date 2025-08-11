
rule Trojan_Win64_Rugmi_HJ_MTB{
	meta:
		description = "Trojan:Win64/Rugmi.HJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 01 00 00 "
		
	strings :
		$a_23_0 = {31 c0 89 c2 66 83 3c 90 01 01 00 90 09 06 00 90 03 01 01 48 4c 8b 90 00 00 } //20
	condition:
		((#a_23_0  & 1)*20) >=20
 
}