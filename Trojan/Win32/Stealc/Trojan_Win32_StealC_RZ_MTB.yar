
rule Trojan_Win32_StealC_RZ_MTB{
	meta:
		description = "Trojan:Win32/StealC.RZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {30 14 38 83 ?? 0f 75 ?? 8d 85 f0 ?? ff ff 50 8d 8d fc ?? ff ff 51 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}
rule Trojan_Win32_StealC_RZ_MTB_2{
	meta:
		description = "Trojan:Win32/StealC.RZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {20 20 20 00 20 20 20 20 00 40 05 00 00 10 00 00 00 58 02 00 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 e0 2e 72 73 72 63 00 00 00 ac 01 00 00 00 50 05 00 00 02 00 00 00 68 02 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}