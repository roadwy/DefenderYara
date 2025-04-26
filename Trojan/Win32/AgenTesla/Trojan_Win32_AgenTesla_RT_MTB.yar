
rule Trojan_Win32_AgenTesla_RT_MTB{
	meta:
		description = "Trojan:Win32/AgenTesla.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {bb 00 01 00 00 01 d8 89 c6 f7 db [0-04] 89 df [0-06] 50 58 8b 04 0a [0-06] 01 f3 0f ef c0 0f ef c9 [0-06] 0f 6e c0 [0-04] 0f 6e 0b [0-06] 0f ef c1 51 50 58 0f 7e c1 [0-04] 88 c8 [0-04] 59 [0-04] 29 f3 83 c3 01 75 ?? 50 58 89 fb [0-06] 90 05 10 01 90 89 04 0a 90 05 10 03 90 d9 d0 83 c1 01 75 b3 } //1
		$a_00_1 = {50 58 51 59 ff e0 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}