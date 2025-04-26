
rule Trojan_Win32_Rozena_GG_MTB{
	meta:
		description = "Trojan:Win32/Rozena.GG!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f 10 40 e0 8d 40 40 83 c1 40 0f 28 ca 66 0f ef c2 0f 11 40 a0 0f 10 40 b0 66 0f ef c2 0f 11 40 b0 0f 10 40 c0 66 0f ef c2 0f 11 40 c0 0f 10 40 d0 66 0f ef c8 0f 11 48 d0 3b ca 72 c3 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}