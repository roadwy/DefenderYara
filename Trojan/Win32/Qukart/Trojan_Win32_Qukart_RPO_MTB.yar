
rule Trojan_Win32_Qukart_RPO_MTB{
	meta:
		description = "Trojan:Win32/Qukart.RPO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {90 31 30 90 90 90 90 90 90 01 f8 90 90 90 90 e2 ef } //1
		$a_01_1 = {89 c8 90 90 90 90 90 90 f7 f7 90 90 90 91 90 90 90 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}