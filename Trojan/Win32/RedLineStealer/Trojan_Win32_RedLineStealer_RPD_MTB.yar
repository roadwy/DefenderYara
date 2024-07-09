
rule Trojan_Win32_RedLineStealer_RPD_MTB{
	meta:
		description = "Trojan:Win32/RedLineStealer.RPD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {eb 01 2b e8 00 00 00 00 90 13 5a 90 13 8b 42 ?? 90 90 90 90 90 90 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}