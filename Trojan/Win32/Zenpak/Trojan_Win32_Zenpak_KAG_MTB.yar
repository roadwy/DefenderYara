
rule Trojan_Win32_Zenpak_KAG_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.KAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_80_0 = {34 6f 6e 65 62 72 6f 75 67 68 74 4a 64 61 72 6b 6e 65 73 73 68 61 64 77 61 73 2e 43 73 } //4onebroughtJdarknesshadwas.Cs  01 00 
		$a_80_1 = {70 67 6f 64 2e 38 42 72 69 6e 67 79 65 61 72 73 } //pgod.8Bringyears  01 00 
		$a_80_2 = {68 69 6e 67 62 65 61 73 74 6c 73 65 61 73 6f 6e 73 5a } //hingbeastlseasonsZ  00 00 
	condition:
		any of ($a_*)
 
}