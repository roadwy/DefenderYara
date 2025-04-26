
rule Trojan_Win32_RedLineStealer_EN_MTB{
	meta:
		description = "Trojan:Win32/RedLineStealer.EN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 7d 08 f6 17 80 2f 8f 47 e2 f8 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}
rule Trojan_Win32_RedLineStealer_EN_MTB_2{
	meta:
		description = "Trojan:Win32/RedLineStealer.EN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 7d 08 f6 17 80 2f 9d 80 2f 35 47 e2 f5 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}