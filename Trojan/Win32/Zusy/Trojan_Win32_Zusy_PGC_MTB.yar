
rule Trojan_Win32_Zusy_PGC_MTB{
	meta:
		description = "Trojan:Win32/Zusy.PGC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {2e 74 65 78 74 00 00 00 10 6f 00 00 00 10 00 00 00 70 00 00 00 04 00 00 00 00 00 00 00 00 00 00 00 00 00 00 20 00 00 e0 } //1
		$a_03_1 = {2e 72 64 61 74 61 00 00 34 6b 07 00 00 ?? 00 00 00 6c 07 00 00 7a 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0 } //4
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*4) >=5
 
}