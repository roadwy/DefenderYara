
rule Trojan_BAT_Loki_KAC_MTB{
	meta:
		description = "Trojan:BAT/Loki.KAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 "
		
	strings :
		$a_01_0 = {66 4d 6c 6f 37 39 50 38 44 2b 6a 2f 70 50 4c 4c 37 76 79 47 31 50 32 50 63 } //4 fMlo79P8D+j/pPLL7vyG1P2Pc
		$a_01_1 = {4e 47 58 30 6e 4f 75 2f 62 6c 50 76 34 4e 57 6d 56 6c 44 77 65 66 67 4d 6a 57 64 } //3 NGX0nOu/blPv4NWmVlDwefgMjWd
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*3) >=7
 
}