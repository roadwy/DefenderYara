
rule Trojan_Win32_Neoreblamy_BM_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.BM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {33 c6 99 52 50 e8 } //5
		$a_01_1 = {83 ec 30 53 56 57 8b f1 89 65 f0 33 db 89 75 e8 56 8d 4d d0 8b fb e8 } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}