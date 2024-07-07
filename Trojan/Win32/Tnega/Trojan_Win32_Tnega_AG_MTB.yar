
rule Trojan_Win32_Tnega_AG_MTB{
	meta:
		description = "Trojan:Win32/Tnega.AG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {81 ea 01 00 00 00 4a 31 19 4a 81 c6 90 01 04 41 39 c1 75 da 29 f2 c3 90 00 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}