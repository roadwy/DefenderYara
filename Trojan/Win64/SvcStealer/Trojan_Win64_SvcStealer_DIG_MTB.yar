
rule Trojan_Win64_SvcStealer_DIG_MTB{
	meta:
		description = "Trojan:Win64/SvcStealer.DIG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 63 ca 8d 42 87 ff c2 42 30 44 21 0a 83 fa 57 72 ee } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}