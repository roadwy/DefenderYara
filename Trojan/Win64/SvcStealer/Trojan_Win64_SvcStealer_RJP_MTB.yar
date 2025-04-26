
rule Trojan_Win64_SvcStealer_RJP_MTB{
	meta:
		description = "Trojan:Win64/SvcStealer.RJP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {65 48 8b 0c 25 30 00 00 00 48 8b 51 60 48 89 5a 10 48 8b 45 e8 48 03 c3 ff d0 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}