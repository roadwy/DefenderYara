
rule Trojan_Win32_Astaroth_psyR_MTB{
	meta:
		description = "Trojan:Win32/Astaroth.psyR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 "
		
	strings :
		$a_01_0 = {e8 9d ff ff ff a1 b0 70 40 00 50 e8 6e ff ff ff 85 c0 74 01 c3 a1 5c 86 40 00 c3 50 e8 5d ff ff ff 85 c0 74 db } //7
	condition:
		((#a_01_0  & 1)*7) >=7
 
}