
rule Trojan_Win32_Stelega_EANX_MTB{
	meta:
		description = "Trojan:Win32/Stelega.EANX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_02_0 = {b1 09 f6 d0 32 c2 2a c8 80 f1 c6 2a ca d0 c9 80 f1 8e f6 d9 80 f1 a8 88 8a ?? ?? ?? ?? 42 81 fa 05 50 00 00 } //5
	condition:
		((#a_02_0  & 1)*5) >=5
 
}