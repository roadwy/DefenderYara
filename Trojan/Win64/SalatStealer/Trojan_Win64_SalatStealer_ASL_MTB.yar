
rule Trojan_Win64_SalatStealer_ASL_MTB{
	meta:
		description = "Trojan:Win64/SalatStealer.ASL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 14 01 83 f2 55 88 14 08 48 ff c1 48 39 cb 7f ee 48 89 d9 48 89 c3 31 c0 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}