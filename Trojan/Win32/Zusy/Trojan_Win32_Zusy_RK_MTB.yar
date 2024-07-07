
rule Trojan_Win32_Zusy_RK_MTB{
	meta:
		description = "Trojan:Win32/Zusy.RK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f 11 84 24 90 01 04 c7 84 24 90 01 08 0f 28 05 90 01 04 0f 11 84 24 90 01 04 66 90 01 01 8a 84 24 08 01 00 00 30 84 0c 09 01 00 00 41 81 f9 d2 00 00 00 72 e9 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}