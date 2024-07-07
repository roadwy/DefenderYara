
rule Trojan_Win32_AveMaria_AG_MTB{
	meta:
		description = "Trojan:Win32/AveMaria.AG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {f7 e6 8b c6 c1 ea 90 01 01 8d 0c 92 c1 e1 90 01 01 2b c1 8a 44 05 90 01 01 30 86 90 01 04 46 81 fe 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}