
rule Trojan_Win32_Zenpak_U_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.U!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 e8 50 8f 05 90 01 04 48 42 83 f2 90 01 01 8d 05 90 01 04 89 18 8d 05 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}