
rule Trojan_Win32_Copak_RK_MTB{
	meta:
		description = "Trojan:Win32/Copak.RK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {21 df 68 c3 94 1f 9f 5b b9 00 00 00 00 89 d7 c3 89 fa 00 75 05 bb 00 00 00 00 40 89 c0 c3 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}