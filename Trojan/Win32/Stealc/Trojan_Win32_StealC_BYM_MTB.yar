
rule Trojan_Win32_StealC_BYM_MTB{
	meta:
		description = "Trojan:Win32/StealC.BYM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {88 45 d0 0f 92 c0 34 7f 83 fb 7e 0f b6 c0 0f 42 c3 89 45 ?? 8b 01 29 f8 83 f8 01 0f b6 42 0f 0f b6 52 ?? 88 55 d8 77 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}