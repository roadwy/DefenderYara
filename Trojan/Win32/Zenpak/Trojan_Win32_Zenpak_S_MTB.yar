
rule Trojan_Win32_Zenpak_S_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.S!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 01 d0 48 89 d8 50 8f 05 90 01 04 8d 05 90 01 04 01 28 31 c2 42 40 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}