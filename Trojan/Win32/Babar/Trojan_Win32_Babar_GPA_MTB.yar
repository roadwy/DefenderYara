
rule Trojan_Win32_Babar_GPA_MTB{
	meta:
		description = "Trojan:Win32/Babar.GPA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 f7 89 f0 31 db 83 c7 5c 81 2e 90 01 04 83 c6 04 66 ba 90 01 02 39 fe 7c ef 90 00 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}