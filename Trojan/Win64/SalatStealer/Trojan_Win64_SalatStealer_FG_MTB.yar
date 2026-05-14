
rule Trojan_Win64_SalatStealer_FG_MTB{
	meta:
		description = "Trojan:Win64/SalatStealer.FG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 35 78 60 ee 00 0f b6 14 16 31 ea 8b 6c 24 50 88 14 2b 8d 45 01 8d 15 78 48 ed 00 39 42 04 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}