
rule Trojan_Win32_Simda_MX_MTB{
	meta:
		description = "Trojan:Win32/Simda.MX!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b da d1 e3 ff 13 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}