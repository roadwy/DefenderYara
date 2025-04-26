
rule Trojan_Win32_Zusy_AMCX_MTB{
	meta:
		description = "Trojan:Win32/Zusy.AMCX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {20 20 00 80 06 00 00 10 00 00 00 80 06 00 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 e0 2e 72 73 72 63 00 00 00 d4 05 00 00 00 90 06 00 00 06 00 00 00 90 06 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}