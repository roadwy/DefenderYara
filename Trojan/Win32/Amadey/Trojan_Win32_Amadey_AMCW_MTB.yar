
rule Trojan_Win32_Amadey_AMCW_MTB{
	meta:
		description = "Trojan:Win32/Amadey.AMCW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {20 20 20 00 80 06 00 00 10 00 00 00 de 02 00 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 e0 2e 72 73 72 63 00 00 00 ac 04 00 00 00 90 06 00 00 04 00 00 00 ee 02 00 00 00 00 00 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}