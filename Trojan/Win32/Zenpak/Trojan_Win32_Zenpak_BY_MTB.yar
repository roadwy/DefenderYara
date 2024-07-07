
rule Trojan_Win32_Zenpak_BY_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.BY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 c2 31 35 90 01 04 83 c0 07 42 83 c0 04 83 c2 01 8d 05 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}