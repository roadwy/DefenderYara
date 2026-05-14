
rule Trojan_Win32_Rozena_PGRO_MTB{
	meta:
		description = "Trojan:Win32/Rozena.PGRO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f 10 04 30 0f 57 c1 0f 11 04 30 0f 10 44 06 ?? 0f 57 c1 0f 11 44 06 ?? 0f 10 44 06 ?? 0f 57 c1 0f 11 44 06 ?? 0f 10 44 06 ?? 0f 57 c1 0f 11 44 06 ?? 83 c0 ?? 3b c1 72 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}