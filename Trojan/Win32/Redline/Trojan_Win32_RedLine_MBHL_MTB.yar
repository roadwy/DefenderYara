
rule Trojan_Win32_RedLine_MBHL_MTB{
	meta:
		description = "Trojan:Win32/RedLine.MBHL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 7d 08 f6 17 80 37 86 47 e2 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}