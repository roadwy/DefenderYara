
rule Trojan_Win32_ShadeR_SA_MTB{
	meta:
		description = "Trojan:Win32/ShadeR.SA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8a 14 2e 68 90 02 10 88 54 24 43 90 02 10 00 00 74 90 02 20 8b 0d 90 01 04 8a 54 24 3b 88 14 0e 46 3b f3 7c 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}