
rule Trojan_Win32_PonyStealer_T_MTB{
	meta:
		description = "Trojan:Win32/PonyStealer.T!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {64 8b 1d c0 00 00 00 [0-04] 83 fb 00 74 ?? eb } //1
		$a_03_1 = {8b 04 0a d9 d0 01 f3 0f 6e c0 [0-10] 0f 6e 0b [0-10] 0f ef c1 51 0f 7e c1 [0-10] 88 c8 [0-10] 59 29 f3 83 c3 01 75 ?? [0-10] 89 fb 89 04 0a 83 c1 01 75 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}