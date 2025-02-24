
rule Trojan_Win32_StealC_AZ_MTB{
	meta:
		description = "Trojan:Win32/StealC.AZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b d7 c1 e2 ?? 03 55 ?? 33 55 ?? 33 d1 89 55 ?? 8b 45 ?? 29 45 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}
rule Trojan_Win32_StealC_AZ_MTB_2{
	meta:
		description = "Trojan:Win32/StealC.AZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {20 20 20 00 20 20 20 20 00 10 05 00 00 10 00 00 00 48 02 00 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 e0 2e 72 73 72 63 00 00 00 b0 02 00 00 00 20 05 00 00 04 00 00 00 58 02 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}