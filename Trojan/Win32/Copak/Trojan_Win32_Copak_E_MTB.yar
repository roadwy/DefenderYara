
rule Trojan_Win32_Copak_E_MTB{
	meta:
		description = "Trojan:Win32/Copak.E!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {31 32 01 df 01 df 81 c2 90 01 04 89 db 39 c2 90 00 } //2
		$a_01_1 = {31 03 41 43 21 d2 21 ca 39 f3 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2) >=2
 
}