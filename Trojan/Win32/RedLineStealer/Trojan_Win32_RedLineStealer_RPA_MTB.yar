
rule Trojan_Win32_RedLineStealer_RPA_MTB{
	meta:
		description = "Trojan:Win32/RedLineStealer.RPA!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {eb 02 69 f6 50 eb 02 0f 1c e8 1a 00 00 00 eb 04 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}