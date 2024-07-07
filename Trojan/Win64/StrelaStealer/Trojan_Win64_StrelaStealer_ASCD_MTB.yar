
rule Trojan_Win64_StrelaStealer_ASCD_MTB{
	meta:
		description = "Trojan:Win64/StrelaStealer.ASCD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 57 41 56 41 55 41 54 56 57 55 53 48 81 ec 90 01 03 00 c7 84 24 90 01 03 00 00 00 00 00 81 bc 24 90 01 03 00 cc 0c 00 00 0f 90 01 03 00 00 e9 00 00 00 00 31 c0 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}