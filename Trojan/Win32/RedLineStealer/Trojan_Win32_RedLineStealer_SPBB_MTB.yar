
rule Trojan_Win32_RedLineStealer_SPBB_MTB{
	meta:
		description = "Trojan:Win32/RedLineStealer.SPBB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 70 0c 31 c0 29 c8 31 c9 29 f1 01 c8 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}