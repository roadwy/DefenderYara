
rule Trojan_Win32_Copak_C_MTB{
	meta:
		description = "Trojan:Win32/Copak.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {31 33 09 c0 42 81 c3 90 01 04 29 d0 81 e8 90 01 04 39 fb 75 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}