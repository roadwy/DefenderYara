
rule Trojan_Win32_Tedy_PGC_MTB{
	meta:
		description = "Trojan:Win32/Tedy.PGC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {40 32 e8 32 d8 40 32 f8 40 32 f0 40 80 f5 5a 80 f3 5a 40 80 f7 5a 40 88 2d } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}