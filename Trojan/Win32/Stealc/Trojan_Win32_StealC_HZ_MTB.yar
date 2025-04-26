
rule Trojan_Win32_StealC_HZ_MTB{
	meta:
		description = "Trojan:Win32/StealC.HZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c3 c1 e0 ?? 03 45 ?? 8d 0c 1f 33 c1 33 45 ?? 89 45 ?? 8b 45 ?? 29 45 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}
rule Trojan_Win32_StealC_HZ_MTB_2{
	meta:
		description = "Trojan:Win32/StealC.HZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 04 24 83 2c 24 ?? 0f be 04 32 89 44 24 ?? 8b 04 24 31 44 24 ?? 8a 4c 24 ?? 88 0c 32 42 3b d7 7c } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}
rule Trojan_Win32_StealC_HZ_MTB_3{
	meta:
		description = "Trojan:Win32/StealC.HZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {20 20 20 00 20 20 20 20 00 90 24 00 00 10 00 00 00 62 01 00 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 e0 2e 72 73 72 63 00 00 00 ac 01 00 00 00 a0 24 00 00 02 00 00 00 72 01 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}