
rule Trojan_Win32_Fragtor_AAC_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.AAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {83 e8 01 6a ?? 59 0f 48 c1 8a 4c 05 ?? 30 0c 13 42 3b 55 ?? 7c } //4
		$a_03_1 = {4b 65 72 6e c7 45 ?? 65 6c 33 32 c7 45 ?? 2e 64 6c 6c 88 5d ?? c7 45 ?? 41 64 76 61 c7 45 ?? 70 69 33 32 c7 45 ?? 2e 64 6c 6c } //1
	condition:
		((#a_03_0  & 1)*4+(#a_03_1  & 1)*1) >=5
 
}