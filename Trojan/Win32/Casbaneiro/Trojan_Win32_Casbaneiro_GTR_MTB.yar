
rule Trojan_Win32_Casbaneiro_GTR_MTB{
	meta:
		description = "Trojan:Win32/Casbaneiro.GTR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {4b 00 33 00 66 00 44 00 64 00 45 00 51 00 53 00 56 00 38 00 56 00 38 } //5
		$a_01_1 = {4e 00 42 00 77 00 71 00 39 00 32 00 77 } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}