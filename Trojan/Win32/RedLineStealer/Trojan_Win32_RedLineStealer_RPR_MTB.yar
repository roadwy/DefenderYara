
rule Trojan_Win32_RedLineStealer_RPR_MTB{
	meta:
		description = "Trojan:Win32/RedLineStealer.RPR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {c1 e0 17 31 45 fc 8b 45 fc c1 f8 11 31 45 fc 8b 45 f8 31 45 fc 8b 45 f8 c1 f8 1a 31 45 fc } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}