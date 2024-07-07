
rule Trojan_Win32_Cridex_DBA_MTB{
	meta:
		description = "Trojan:Win32/Cridex.DBA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {ba b4 12 00 00 ba bc 01 00 00 a1 90 01 04 a3 90 1b 00 eb 00 eb 00 31 0d 90 1b 00 c7 05 90 01 04 00 00 00 00 a1 90 1b 00 01 05 90 01 04 a1 90 01 04 8b 0d 90 01 04 89 08 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}