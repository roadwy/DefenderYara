
rule Trojan_Win32_Banker_RA_MTB{
	meta:
		description = "Trojan:Win32/Banker.RA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {42 83 fa 08 7c 90 09 34 00 8b c6 81 c6 90 01 04 35 90 01 04 69 c8 90 01 04 81 f1 90 01 04 8b c1 c1 e8 0d 33 c1 69 c8 90 01 04 8b c1 c1 e8 0f 33 c1 89 84 94 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}