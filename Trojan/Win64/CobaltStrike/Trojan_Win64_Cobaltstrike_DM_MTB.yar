
rule Trojan_Win64_Cobaltstrike_DM_MTB{
	meta:
		description = "Trojan:Win64/Cobaltstrike.DM!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 07 4c 8d 44 24 30 34 45 48 63 ee 49 03 ee 88 44 24 30 48 8b d5 4c 89 6c 24 20 41 b9 01 00 00 00 49 8b cf 41 ff d4 85 c0 75 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}