
rule Trojan_Win32_RedLineStealer_N_MTB{
	meta:
		description = "Trojan:Win32/RedLineStealer.N!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c0 33 db f6 17 80 37 ?? 47 e2 ?? 5f 5e 5b } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}