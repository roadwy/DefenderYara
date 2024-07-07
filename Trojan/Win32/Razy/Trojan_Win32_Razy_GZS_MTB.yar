
rule Trojan_Win32_Razy_GZS_MTB{
	meta:
		description = "Trojan:Win32/Razy.GZS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {21 f8 47 bb 90 01 04 81 c0 90 01 04 e8 90 01 04 21 c7 01 c0 31 1a 48 81 c0 90 01 04 81 c2 90 01 04 81 e8 c6 34 00 c0 09 c0 39 f2 75 d1 29 f8 c3 90 00 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}